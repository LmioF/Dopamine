#import <Foundation/Foundation.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/event.h>
#include <sys/syscall.h>
#include <libgen.h>

#include "../libjailbreak.h"
#include "../info.h"
#include "unsandbox.h"
#include "common.h"
#include "namecache_transaction.h"
#include "log.h"

// ==================== iOS 16.4 xnu-8796 use smrq_link ====================

#define SMR_POINTER_DECL(name, type_t) \
	struct name { type_t volatile __smr_ptr; }

#define SMR_POINTER(type_t) \
	SMR_POINTER_DECL(, type_t)

typedef SMR_POINTER(struct smrq_link *)  __smrq_link_t;

struct smrq_link {
    struct smrq_link *           le_next;
    struct smrq_link *          *le_prev;
};


struct  namecache_v2 {
    TAILQ_ENTRY(namecache_v2)  nc_entry;       /* chain of all entries */
    TAILQ_ENTRY(namecache_v2)  nc_child;       /* chain of ncp's that are children of a vp */
    union {
        LIST_ENTRY(namecache_v2)  nc_link; /* chain of ncp's that 'name' a vp */
        TAILQ_ENTRY(namecache_v2) nc_negentry; /* chain of ncp's that 'name' a vp */
    } nc_un;
    struct smrq_link        nc_hash;        /* hash chain */
    uint32_t                nc_vid;         /* vid for nc_vp */
    uint32_t                nc_counter;     /* flags */
    vnode_t                 nc_dvp;         /* vnode of parent of name */
    vnode_t                 nc_vp;          /* vnode the name refers to */
    unsigned int            nc_hashval;     /* hashval of stringname */
    const char              *nc_name;       /* pointer to segment name in string cache */
};

#define namecache namecache_v2

#ifdef ENABLE_LOGS
enum { NC_DIAGNOSTIC_LIMIT = 128 };

static void print_nc(uint64_t ncp) 
{
	for (unsigned visited = 0; ncp && visited < NC_DIAGNOSTIC_LIMIT; visited++) {

		struct namecache nc={0};
		if (kreadbuf(ncp, &nc, sizeof(nc)) != 0) break;

		char namebuf[128]={0};
		for(size_t i = 0; nc.nc_name && i < sizeof(namebuf) - 1; i++)
			if( !(namebuf[i]=kread8((uint64_t)nc.nc_name+i)) ) break;

		JBLogDebug("nc %llx hashval=%08x vp=%16llx dvp=%llx name=%llx next=%16llx prev=%llx,%llx %s\n", ncp, nc.nc_hashval, nc.nc_vp, nc.nc_dvp, nc.nc_name, 
				nc.nc_hash.le_next, nc.nc_hash.le_prev, nc.nc_hash.le_prev?kread64((uint64_t) nc.nc_hash.le_prev):0, namebuf);

		ncp = (uint64_t)nc.nc_hash.le_next;
	}
}

static void print_nc2(uint64_t ncp)
{
    for (unsigned visited = 0; ncp && visited < NC_DIAGNOSTIC_LIMIT; visited++) {

        if (ncp < offsetof(struct namecache_v2, nc_hash)) break;
        ncp -= offsetof(struct namecache_v2, nc_hash);
        
        struct namecache nc={0};
        if (kreadbuf(ncp, &nc, sizeof(nc)) != 0) break;

        char namebuf[128]={0};
        for(size_t i = 0; nc.nc_name && i < sizeof(namebuf) - 1; i++)
            if( !(namebuf[i]=kread8((uint64_t)nc.nc_name+i)) ) break;

        JBLogDebug("nc %llx hashval=%08x vp=%16llx dvp=%llx name=%llx next=%16llx prev=%llx,%llx %s\n", ncp, nc.nc_hashval, nc.nc_vp, nc.nc_dvp, nc.nc_name,
            nc.nc_hash.le_next, nc.nc_hash.le_prev, nc.nc_hash.le_prev ? kread64((uint64_t) nc.nc_hash.le_prev):0, namebuf);

        ncp = (uint64_t)nc.nc_hash.le_next;
    }
}
#endif

static int make_tail_file(char tail[PATH_MAX], int *tailfd)
{
    snprintf(tail, PATH_MAX, "/tmp/roothide-tail.XXXXXX");
    *tailfd = mkstemp(tail);
    if (*tailfd < 0) {
        tail[0] = '\0';
        return -1;
    }
    uint64_t tailvp = proc_fd_vnode(proc_self(), *tailfd);
    if (tailvp == 0) {
        errno = EIO;
        return -1;
    }
    JBLogDebug("tail=%s fd=%d vnode=%llx", tail, *tailfd, tailvp);
    return 0;
}

static int validate_namecache_v2_topology(uint64_t filevp, uint64_t filencp, uint32_t hash_val,
                                          uint64_t *parentvp_out, struct namecache *filenc_out)
{
    struct vnode filevnode = {0};
    struct vnode parentvnode = {0};
    struct namecache filenc = {0};
    if (kreadbuf(filevp, &filevnode, sizeof(filevnode)) != 0 ||
        kreadbuf(filencp, &filenc, sizeof(filenc)) != 0) {
        errno = EIO;
        return -1;
    }

    uint64_t parentvp = UNSIGN_PTR((uint64_t)filevnode.v_parent);
    uint64_t hash_link = filencp + offsetof(struct namecache, nc_hash);
    if (!parentvp || (uint64_t)filevnode.v_nclinks.lh_first != filencp ||
        (uint64_t)filenc.nc_vp != filevp || (uint64_t)filenc.nc_dvp != parentvp ||
        filenc.nc_vid != filevnode.v_id || filenc.nc_hashval != hash_val || !(filenc.nc_counter & 1U) ||
        !filenc.nc_entry.tqe_next || !filenc.nc_entry.tqe_prev || !filenc.nc_hash.le_prev ||
        !filenc.nc_child.tqe_prev || !filenc.nc_un.nc_link.le_prev) {
        errno = EINVAL;
        return -1;
    }
    if (kreadbuf(parentvp, &parentvnode, sizeof(parentvnode)) != 0) {
        errno = EIO;
        return -1;
    }

    if (rh_namecache_expect64((uint64_t)filenc.nc_entry.tqe_prev, filencp) != 0 ||
        rh_namecache_expect64((uint64_t)filenc.nc_entry.tqe_next + offsetof(struct namecache, nc_entry.tqe_prev),
                              filencp + offsetof(struct namecache, nc_entry.tqe_next)) != 0 ||
        rh_namecache_expect64((uint64_t)filenc.nc_hash.le_prev, hash_link) != 0 ||
        rh_namecache_expect64((uint64_t)filenc.nc_child.tqe_prev, filencp) != 0 ||
        rh_namecache_expect64((uint64_t)filenc.nc_un.nc_link.le_prev, filencp) != 0) {
        return -1;
    }
    if (filenc.nc_hash.le_next &&
        rh_namecache_expect64((uint64_t)filenc.nc_hash.le_next + offsetof(struct smrq_link, le_prev),
                              filencp + offsetof(struct namecache, nc_hash.le_next)) != 0) {
        return -1;
    }
    if (filenc.nc_child.tqe_next) {
        if (rh_namecache_expect64((uint64_t)filenc.nc_child.tqe_next + offsetof(struct namecache, nc_child.tqe_prev),
                                  filencp + offsetof(struct namecache, nc_child.tqe_next)) != 0) return -1;
    }
    else if ((uint64_t)parentvnode.v_ncchildren.tqh_last !=
             filencp + offsetof(struct namecache, nc_child.tqe_next)) {
        errno = EINVAL;
        return -1;
    }
    if (filenc.nc_un.nc_link.le_next &&
        rh_namecache_expect64((uint64_t)filenc.nc_un.nc_link.le_next + offsetof(struct namecache, nc_un.nc_link.le_prev),
                              filencp + offsetof(struct namecache, nc_un.nc_link.le_next)) != 0) {
        return -1;
    }

    if (parentvp_out) *parentvp_out = parentvp;
    if (filenc_out) *filenc_out = filenc;
    return 0;
}

static int publish_namecache_v2(uint64_t dirvp, uint64_t filevp, uint64_t filencp,
                                uint32_t hash_val, uint64_t ncpp,
                                struct rh_namecache_transaction *transaction,
                                uint32_t *valid_counter_out)
{
    if (!transaction || !valid_counter_out || !dirvp || !filevp || !filencp || !ncpp) {
        errno = EINVAL;
        return -1;
    }
    memset(transaction, 0, sizeof(*transaction));
    *valid_counter_out = 0;
    if (rh_namecache_writer_lock() != 0) return -1;

    int result = -1;
    int saved_errno = EIO;
    uint64_t parentvp = 0;
    struct namecache filenc = {0};
    uint64_t counter_address = filencp + offsetof(struct namecache, nc_counter);
    if (validate_namecache_v2_topology(filevp, filencp, hash_val, &parentvp, &filenc) != 0) {
        saved_errno = errno;
        goto out;
    }
    *valid_counter_out = filenc.nc_counter;
    if (rh_namecache_counter_invalidate(counter_address, filenc.nc_counter) != 0) {
        saved_errno = errno;
        goto out;
    }

    if (rh_namecache_write64(transaction, filencp + offsetof(struct namecache, nc_dvp), dirvp) != 0 ||
        rh_namecache_write64(transaction, filevp + offsetof(struct vnode, v_parent), 0) != 0) {
        saved_errno = errno;
        goto rollback;
    }

    if (filenc.nc_hash.le_next &&
        rh_namecache_write64(transaction, (uint64_t)filenc.nc_hash.le_next + offsetof(struct smrq_link, le_prev),
                             (uint64_t)filenc.nc_hash.le_prev) != 0) {
        saved_errno = errno;
        goto rollback;
    }
    if (rh_namecache_write64(transaction, (uint64_t)filenc.nc_hash.le_prev,
                             (uint64_t)filenc.nc_hash.le_next) != 0) {
        saved_errno = errno;
        goto rollback;
    }

    uint64_t first = 0;
    uint64_t hash_link = filencp + offsetof(struct namecache, nc_hash);
    if (rh_namecache_read64(ncpp, &first) != 0 || first == hash_link) {
        saved_errno = first == hash_link ? EINVAL : errno;
        goto rollback;
    }
    if (first && rh_namecache_expect64(first + offsetof(struct smrq_link, le_prev), ncpp) != 0) {
        saved_errno = errno;
        goto rollback;
    }
    if (rh_namecache_write64(transaction, filencp + offsetof(struct namecache, nc_hash.le_next), first) != 0 ||
        (first && rh_namecache_write64(transaction, first + offsetof(struct smrq_link, le_prev),
                                       filencp + offsetof(struct namecache, nc_hash.le_next)) != 0) ||
        rh_namecache_write64(transaction, ncpp, hash_link) != 0 ||
        rh_namecache_write64(transaction, filencp + offsetof(struct namecache, nc_hash.le_prev), ncpp) != 0) {
        saved_errno = errno;
        goto rollback;
    }

    if (filenc.nc_child.tqe_next) {
        if (rh_namecache_write64(transaction,
                                 (uint64_t)filenc.nc_child.tqe_next + offsetof(struct namecache, nc_child.tqe_prev),
                                 (uint64_t)filenc.nc_child.tqe_prev) != 0) {
            saved_errno = errno;
            goto rollback;
        }
    }
    else if (rh_namecache_write64(transaction, parentvp + offsetof(struct vnode, v_ncchildren.tqh_last),
                                  (uint64_t)filenc.nc_child.tqe_prev) != 0) {
        saved_errno = errno;
        goto rollback;
    }
    if (rh_namecache_write64(transaction, (uint64_t)filenc.nc_child.tqe_prev,
                             (uint64_t)filenc.nc_child.tqe_next) != 0 ||
        rh_namecache_write64(transaction, filencp + offsetof(struct namecache, nc_child.tqe_next), filencp) != 0 ||
        rh_namecache_write64(transaction, filencp + offsetof(struct namecache, nc_child.tqe_prev),
                             filencp + offsetof(struct namecache, nc_child.tqe_next)) != 0) {
        saved_errno = errno;
        goto rollback;
    }

    if (rh_namecache_write64(transaction,
                             (uint64_t)filenc.nc_entry.tqe_next + offsetof(struct namecache, nc_entry.tqe_prev),
                             (uint64_t)filenc.nc_entry.tqe_prev) != 0 ||
        rh_namecache_write64(transaction, (uint64_t)filenc.nc_entry.tqe_prev,
                             (uint64_t)filenc.nc_entry.tqe_next) != 0 ||
        rh_namecache_write64(transaction, filencp + offsetof(struct namecache, nc_entry.tqe_next), filencp) != 0 ||
        rh_namecache_write64(transaction, filencp + offsetof(struct namecache, nc_entry.tqe_prev),
                             filencp + offsetof(struct namecache, nc_entry.tqe_next)) != 0) {
        saved_errno = errno;
        goto rollback;
    }

    if (filenc.nc_un.nc_link.le_next &&
        rh_namecache_write64(transaction,
                             (uint64_t)filenc.nc_un.nc_link.le_next + offsetof(struct namecache, nc_un.nc_link.le_prev),
                             (uint64_t)filenc.nc_un.nc_link.le_prev) != 0) {
        saved_errno = errno;
        goto rollback;
    }
    if (rh_namecache_write64(transaction, (uint64_t)filenc.nc_un.nc_link.le_prev,
                             (uint64_t)filenc.nc_un.nc_link.le_next) != 0 ||
        rh_namecache_transaction_matches_new(transaction) != 0) {
        saved_errno = errno;
        goto rollback;
    }

    if (rh_namecache_counter_publish(counter_address, filenc.nc_counter + 1U) != 0) {
        saved_errno = errno;
        goto rollback;
    }
    result = 0;
    goto out;

rollback:
    if (rh_namecache_transaction_rollback(transaction) != 0 ||
        rh_namecache_transaction_matches_old(transaction) != 0) {
        saved_errno = EIO;
        goto out;
    }
    if (rh_namecache_counter_publish(counter_address, filenc.nc_counter + 1U) != 0) {
        saved_errno = EIO;
        goto out;
    }

out:
    if (rh_namecache_writer_unlock() != 0) {
        result = -1;
        saved_errno = EIO;
    }
    if (result != 0) errno = saved_errno;
    return result;
}

static int rollback_namecache_v2(const struct rh_namecache_transaction *transaction,
                                 uint64_t filencp, uint32_t previous_valid_counter)
{
    if (!transaction || !transaction->count || !filencp || !(previous_valid_counter & 1U)) return 0;
    if (rh_namecache_writer_lock() != 0) return -1;

    int result = -1;
    int saved_errno = EIO;
    uint64_t counter_address = filencp + offsetof(struct namecache, nc_counter);
    uint32_t current_counter = 0;
    if (rh_namecache_read32(counter_address, &current_counter) != 0 ||
        current_counter != previous_valid_counter + 2U ||
        rh_namecache_transaction_matches_new(transaction) != 0) {
        saved_errno = errno;
        goto out;
    }
    if (rh_namecache_counter_invalidate(counter_address, current_counter) != 0) {
        saved_errno = errno;
        goto out;
    }
    if (rh_namecache_transaction_rollback(transaction) != 0 ||
        rh_namecache_transaction_matches_old(transaction) != 0) {
        saved_errno = EIO;
        goto out;
    }
    if (rh_namecache_counter_publish(counter_address, current_counter + 1U) != 0) {
        saved_errno = EIO;
        goto out;
    }
    result = 0;

out:
    if (rh_namecache_writer_unlock() != 0) {
        result = -1;
        saved_errno = EIO;
    }
    if (result != 0) errno = saved_errno;
    return result;
}

int unsandbox2(const char* dir, const char* file)
{
		int ret = 0;
		int filefd=-1,dirfd=-1,newfilefd=-1;
		int tailfd = -1;
		char tail[PATH_MAX] = {0};
		uint64_t dirvp = 0, filevp = 0, parentvp = 0;
		bool dirRef = false, fileRef = false, parentRef = false;
		bool retainRefsOnExit = false;

	 dirfd = open(dir, O_RDONLY);
	if(dirfd<0) {
		JBLogError("open dir failed %d,%s", errno, strerror(errno));
		goto failed;
	}

	 filefd = open(file, O_RDONLY);
	if(filefd<0) {
		JBLogError("open file failed %d,%s", errno, strerror(errno));
		goto failed;
	}
	
	/* we need to create a new namecache to add to the tail of nchead 
        after the kernel caches the namecache for "file" to avoid filenc.nc_entry.tqe_next==0 */
    if(make_tail_file(tail, &tailfd) != 0) {
        JBLogError("make_tail_file failed %d,%s", errno, strerror(errno));
        goto failed;
    }

	    dirvp = proc_fd_vnode(proc_self(), dirfd);
		if(!dirvp) {
			JBLogError("get dirvp failed %d,%s", errno, strerror(errno));
			goto failed;
		}
		if (rh_namecache_retain_vnode(dirvp) != 0) {
			JBLogError("retain dir vnode failed %d,%s", errno, strerror(errno));
			goto failed;
		}
		dirRef = true;

		struct vnode dirvnode = {0};
		if (kreadbuf(dirvp, &dirvnode, sizeof(dirvnode)) != 0) {
			JBLogError("read dir vnode failed");
			goto failed;
		}

	    filevp = proc_fd_vnode(proc_self(), filefd);
		if(!filevp) {
			JBLogError("get filevp failed %d,%s", errno, strerror(errno));
			goto failed;
		}
		if (rh_namecache_retain_vnode(filevp) != 0) {
			JBLogError("retain file vnode failed %d,%s", errno, strerror(errno));
			goto failed;
		}
		fileRef = true;

		struct vnode filevnode = {0};
		if (kreadbuf(filevp, &filevnode, sizeof(filevnode)) != 0) {
			JBLogError("read file vnode failed");
			goto failed;
		}

		struct vnode parentvnode = {0};
	    parentvp = UNSIGN_PTR((uint64_t) filevnode.v_parent);
		if (!parentvp || rh_namecache_retain_vnode(parentvp) != 0) {
			JBLogError("retain parent vnode failed %d,%s", errno, strerror(errno));
			goto failed;
		}
		parentRef = true;
		if (kreadbuf(parentvp, &parentvnode, sizeof(parentvnode)) != 0) {
			JBLogError("read parent vnode failed");
			goto failed;
		}

	JBLogDebug("filefd=%d filevp=%llx/%d fileid=%lld parent=%llx/%d dirvp=%llx dirid=%lld ncchildren=%llx:%llx->%llx\n", 
		filefd, filevp,filevnode.v_usecount, filevnode.v_id, filevnode.v_parent, parentvnode.v_usecount, dirvp, dirvnode.v_id, dirvnode.v_ncchildren.tqh_first, dirvnode.v_ncchildren.tqh_last, 
		dirvnode.v_ncchildren.tqh_last?kread64((uint64_t)dirvnode.v_ncchildren.tqh_last):0);

    // char parentname[32]={0};
    // kreadbuf((uint64_t)parentvnode.v_name, parentname, sizeof(parentname));
    // JBLogDebug("parentname=%s\n", parentname);


		struct namecache filenc={0};
		uint64_t filencp = (uint64_t)filevnode.v_nclinks.lh_first;
		if (!filencp || kreadbuf(filencp, &filenc, sizeof(filenc)) != 0) {
			JBLogError("read file namecache failed");
			goto failed;
		}
    JBLogDebug("filenc=%llx vp=%llx dvp=%llx\n", filencp, filenc.nc_vp, filenc.nc_dvp);

#ifdef ENABLE_LOGS
{
	uint64_t ncp=(uint64_t)dirvnode.v_ncchildren.tqh_first;
	for (unsigned visited = 0; ncp && visited < NC_DIAGNOSTIC_LIMIT; visited++) {

		struct namecache nc={0};
		if (kreadbuf(ncp, &nc, sizeof(nc)) != 0) break;

		char namebuf[128]={0};
		for(size_t i = 0; nc.nc_name && i < sizeof(namebuf) - 1; i++)
			if( !(namebuf[i]=kread8((uint64_t)nc.nc_name+i)) ) break;

		JBLogDebug("child %llx hashval=%08x vp=%16llx dvp=%llx name=%llx next=%16llx prev=%llx,%llx %s\n", ncp, nc.nc_hashval, nc.nc_vp, nc.nc_dvp, nc.nc_name, 
				nc.nc_child.tqe_next, nc.nc_child.tqe_prev, nc.nc_child.tqe_prev?kread64((uint64_t) nc.nc_child.tqe_prev):0, namebuf);

		ncp = (uint64_t)nc.nc_child.tqe_next;
	}
}
#endif

	init_crc32();
	char fname[PATH_MAX];
	uint32_t hash_val = hash_string(basename_r(file, fname), 0);
	JBLogDebug("hash=%x\n", hash_val);

	uint64_t kernelslide = gSystemInfo.kernelConstant.slide;
	JBLogDebug("kernelslide=%llx\n", kernelslide);
		uint64_t nchashtbl = 0, nchashmask = 0;
		if (rh_namecache_read64(ksymbol(nchashtbl), &nchashtbl) != 0 ||
		    rh_namecache_read64(ksymbol(nchashmask), &nchashmask) != 0 || !nchashtbl) {
			JBLogError("read namecache globals failed");
			goto failed;
		}
	JBLogDebug("nchashtbl=%llx nchashmask=%llx\n", nchashtbl, nchashmask);
	// for(int i=0; i<nchashmask; i++) {
	// 	JBLogDebug("hash[%d]=%llx\n", i, kread64(nchashtbl+i*8));
	// }

	uint32_t index = (dirvnode.v_id ^ (hash_val)) & nchashmask; //*********dirv2?
	uint64_t ncpp = nchashtbl + index*8;
	JBLogDebug("index=%x ncpp=%llx ncp=%llx\n", index, ncpp, kread64(ncpp));

#ifdef ENABLE_LOGS
	JBLogDebug("dir hash chain\n");
	print_nc2(kread64(ncpp));
#endif
	

		struct rh_namecache_transaction publication = {0};
		uint32_t publication_counter = 0;
			if (publish_namecache_v2(dirvp, filevp, filencp, hash_val, ncpp,
			                         &publication, &publication_counter) != 0) {
				JBLogError("namecache publication failed %d,%s", errno, strerror(errno));
				goto failed;
			}
			retainRefsOnExit = true;

#ifdef ENABLE_LOGS
	JBLogDebug("final hash chain\n");
	print_nc2(kread64(ncpp));
#endif


	JBLogDebug("unsandboxed %llx %llx %s %s\n\n", filevp, dirvp, file, dir);

    //update v_parent
    char newfile[PATH_MAX]={0};
    snprintf(newfile,sizeof(newfile),"%s/%s",dir,basename_r(file, fname));
    JBLogDebug("newfile=%s\n", newfile);

		newfilefd = open(newfile, O_RDONLY);
	    if(newfilefd < 0) {
			JBLogError("open newfile failed %d,%s", errno, strerror(errno));
				if (rollback_namecache_v2(&publication, filencp, publication_counter) != 0) {
					JBLogError("namecache rollback failed %d,%s", errno, strerror(errno));
				}
				else {
					retainRefsOnExit = false;
				}
				goto failed;
		}

    char pathbuf[PATH_MAX]={0};
    int ret1=fcntl(newfilefd, F_GETPATH, pathbuf);
    JBLogDebug("realpath=(%d) %s\n", ret1, pathbuf);
		if(ret1 != 0) {
			JBLogError("get realpath failed after successful namecache publication %d,%s", errno, strerror(errno));
		}

	goto final;

failed:
	ret = -1;

final:
		if (!retainRefsOnExit) {
			if (parentRef && rh_namecache_release_vnode(parentvp) != 0) JBLogError("release parent vnode failed %d", errno);
			if (fileRef && rh_namecache_release_vnode(filevp) != 0) JBLogError("release file vnode failed %d", errno);
			if (dirRef && rh_namecache_release_vnode(dirvp) != 0) JBLogError("release dir vnode failed %d", errno);
		}
		if (tail[0] && unlink(tail) != 0) JBLogError("unlink tail %s failed: %d", tail, errno);
	if (tailfd >= 0 && close(tailfd) != 0) JBLogError("close tail failed: %d", errno);
	if(dirfd>=0) close(dirfd);
	if(filefd>=0) close(filefd);
	if(newfilefd>=0) close(newfilefd);

	return ret;
}

