```c
// disk inode
struct revofs_inode {
    uint32_t i_mode;   /* File mode */ //dir link file
    uint32_t i_uid;    /* Owner id */
    uint32_t i_gid;    /* Group id */
    uint32_t i_size;   /* Size in bytes */
    uint32_t i_ctime;  /* Inode change time */
    uint32_t i_atime;  /* Access time */
    uint32_t i_mtime;  /* Modification time */
    uint32_t i_blocks; /* Block count */
    uint32_t i_nlink;  /* Hard links count */
    uint32_t ei_block;  /* Block with list of extents for this file */
    char i_data[32]; /* store symlink content */
};

// disk super block
struct revofs_sb_info {
    uint32_t magic; /* Magic number */

    uint32_t nr_blocks; /* Total number of blocks (incl sb & inodes) */
    uint32_t nr_inodes; /* Total number of inodes */

    uint32_t nr_istore_blocks; /* Number of inode store blocks */
    uint32_t nr_ifree_blocks;  /* Number of inode free bitmap blocks */
    uint32_t nr_bfree_blocks;  /* Number of block free bitmap blocks */

    uint32_t nr_free_inodes; /* Number of free inodes */
    uint32_t nr_free_blocks; /* Number of free blocks */

#ifdef __KERNEL__
    unsigned long *ifree_bitmap; /* In-memory free inodes bitmap */
    unsigned long *bfree_bitmap; /* In-memory free blocks bitmap */
#endif
};


// revofs_dir_block disk dir
struct revofs_file {
    uint32_t inode;  // inode number
    char filename[REVOFS_FILENAME_LEN];  // 文件名
};

struct revofs_dir_block {
    struct revofs_file files[REVOFS_FILES_PER_BLOCK];  // 目录数据块中全部存目录项
};



struct file {
	union {
		struct llist_node	fu_llist;
		struct rcu_head 	fu_rcuhead;
	} f_u;
	struct path		f_path;
	struct inode		*f_inode;	/* cached value */
	const struct file_operations	*f_op;

	/*
	 * Protects f_ep, f_flags.
	 * Must not be taken from IRQ context.
	 */
	spinlock_t		f_lock;
	enum rw_hint		f_write_hint;
	atomic_long_t		f_count;
	unsigned int 		f_flags;
	fmode_t			f_mode;
	struct mutex		f_pos_lock;
	loff_t			f_pos;
	struct fown_struct	f_owner;
	const struct cred	*f_cred;
	struct file_ra_state	f_ra;

	u64			f_version;
#ifdef CONFIG_SECURITY
	void			*f_security;
#endif
	/* needed for tty driver, and maybe others */
	void			*private_data;

#ifdef CONFIG_EPOLL
	/* Used by fs/eventpoll.c to link all the hooks to this file */
	struct hlist_head	*f_ep;
#endif /* #ifdef CONFIG_EPOLL */
	struct address_space	*f_mapping;
	errseq_t		f_wb_err;
	errseq_t		f_sb_err; /* for syncfs */
}





// 由root_inode生成根目录dentry /
struct dentry *d_make_root(struct inode *root_inode)
{
	struct dentry *res = NULL;
 
	if (root_inode) {
		static const struct qstr name = QSTR_INIT("/", 1);//该dentry的名字为‘/’，是该文件系统的root dentry
 
		res = __d_alloc(root_inode->i_sb, &name);//分配并初始化dentry
		if (res)
			d_instantiate(res, root_inode);
		else
			iput(root_inode);
	}
	return res;
}

// fs/super.c
// mount_bdev 挂载需要硬盘的文件系统
struct dentry *mount_bdev(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data,
	int (*fill_super)(struct super_block *, void *, int))
{
	struct block_device *bdev;
	struct super_block *s;
    // 初始模式为读，执行
	fmode_t mode = FMODE_READ | FMODE_EXCL;
	int error = 0;
	// 不是只读加入写标志
	if (!(flags & SB_RDONLY))
		mode |= FMODE_WRITE;
	//获取块设备
	bdev = blkdev_get_by_path(dev_name, mode, fs_type);
	if (IS_ERR(bdev))
		return ERR_CAST(bdev);

	/*
	 * once the super is inserted into the list by sget, s_umount
	 * will protect the lockfs code from trying to start a snapshot
	 * while we are mounting
	 */
	mutex_lock(&bdev->bd_fsfreeze_mutex);
	if (bdev->bd_fsfreeze_count > 0) {
		mutex_unlock(&bdev->bd_fsfreeze_mutex);
		error = -EBUSY;
		goto error_bdev;
	}
    // 获取创建超级块
	s = sget(fs_type, test_bdev_super, set_bdev_super, flags | SB_NOSEC,
		 bdev);
	mutex_unlock(&bdev->bd_fsfreeze_mutex);
	if (IS_ERR(s))
		goto error_s;

	if (s->s_root) {
		if ((flags ^ s->s_flags) & SB_RDONLY) {
			deactivate_locked_super(s);
			error = -EBUSY;
			goto error_bdev;
		}

		/*
		 * s_umount nests inside open_mutex during
		 * __invalidate_device().  blkdev_put() acquires
		 * open_mutex and can't be called under s_umount.  Drop
		 * s_umount temporarily.  This is safe as we're
		 * holding an active reference.
		 */
		up_write(&s->s_umount);
		blkdev_put(bdev, mode);
		down_write(&s->s_umount);
	} else {
		s->s_mode = mode;
		snprintf(s->s_id, sizeof(s->s_id), "%pg", bdev);
		sb_set_blocksize(s, block_size(bdev));
		error = fill_super(s, data, flags & SB_SILENT ? 1 : 0);
		if (error) {
			deactivate_locked_super(s);
			goto error;
		}

		s->s_flags |= SB_ACTIVE;
		bdev->bd_super = s;
	}

	return dget(s->s_root);

error_s:
	error = PTR_ERR(s);
error_bdev:
	blkdev_put(bdev, mode);
error:
	return ERR_PTR(error);
}
EXPORT_SYMBOL(mount_bdev);

// kill_sb用于卸载文件系统
static struct file_system_type revofs_file_system_type = {
    .owner = THIS_MODULE,
    .name = "revofs",
    .mount = revofs_mount,
    .kill_sb = revofs_kill_sb,
    .fs_flags = FS_REQUIRES_DEV,
    .next = NULL,
};

void kill_block_super(struct super_block *sb)
{
	struct block_device *bdev = sb->s_bdev;
	fmode_t mode = sb->s_mode;

	bdev->bd_super = NULL;
	generic_shutdown_super(sb);
	sync_blockdev(bdev); //同步将内存中的脏数据全部刷新到设备
	WARN_ON_ONCE(!(mode & FMODE_EXCL));
	blkdev_put(bdev, mode | FMODE_EXCL);
}
```



## write

```c
//write全过程
// fs/read_write.c
// write系统调用其实是转进了ksys_write函数
SYSCALL_DEFINE3(write, unsigned int, fd, const char __user *, buf,
		size_t, count)
{
	return ksys_write(fd, buf, count);
}

ssize_t ksys_write(unsigned int fd, const char __user *buf, size_t count)
{
	struct fd f = fdget_pos(fd);
	ssize_t ret = -EBADF;

	if (f.file) {
		loff_t pos, *ppos = file_ppos(f.file);
		if (ppos) {
			pos = *ppos;
			ppos = &pos;
		}
        // 调用vfs层的写函数
		ret = vfs_write(f.file, buf, count, ppos);
		if (ret >= 0 && ppos)
			f.file->f_pos = pos;
		fdput_pos(f);
	}

	return ret;
}

// vfs层写函数
ssize_t vfs_write(struct file *file, const char __user *buf, size_t count, loff_t *pos)
{
	ssize_t ret;

	if (!(file->f_mode & FMODE_WRITE))
		return -EBADF;
	if (!(file->f_mode & FMODE_CAN_WRITE))
		return -EINVAL;
    // 检查用户空间指针是否有效，以及请求的字节数是否超出用户空间的范围
	if (unlikely(!access_ok(buf, count)))
		return -EFAULT;
	// 验证写操作是否超出文件范围
	ret = rw_verify_area(WRITE, file, pos, count);
	if (ret)
		return ret;
	if (count > MAX_RW_COUNT)
		count =  MAX_RW_COUNT;
	file_start_write(file);
    // write 以及write_iter函数的选择
	if (file->f_op->write)
		ret = file->f_op->write(file, buf, count, pos);
	else if (file->f_op->write_iter)
		ret = new_sync_write(file, buf, count, pos);
	else
		ret = -EINVAL;
	if (ret > 0) {
		fsnotify_modify(file);
		add_wchar(current, ret);
	}
	inc_syscw(current);
	file_end_write(file);
	return ret;
}

// new_sync_write
static ssize_t new_sync_write(struct file *filp, const char __user *buf, size_t len, loff_t *ppos)
{
    // iovec结构描述一个内存区域，起始为用户数剧缓冲，长度为写长度
	struct iovec iov = { .iov_base = (void __user *)buf, .iov_len = len };
    // 描述i/o操作的内核结构
	struct kiocb kiocb;
    // 用于内核空间和用户空间之间迭代传输数据
	struct iov_iter iter;
	ssize_t ret;
	// 初始化kiocb
	init_sync_kiocb(&kiocb, filp);
    // 写操作的起始位置
	kiocb.ki_pos = (ppos ? *ppos : 0);
	iov_iter_init(&iter, WRITE, &iov, 1, len);
	// file_operation
	ret = call_write_iter(filp, &kiocb, &iter);
	BUG_ON(ret == -EIOCBQUEUED);
	if (ret > 0 && ppos)
		*ppos = kiocb.ki_pos;
	return ret;
}

// call_write_iter
static inline ssize_t call_write_iter(struct file *file, struct kiocb *kio,
				      struct iov_iter *iter)
{
	return file->f_op->write_iter(kio, iter);
}

// 如果以generic_file_write_iter实现
// iov_iter用于内核数据和用户数剧之间的迭代传送，kiocb用于I/O操作
ssize_t generic_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file->f_mapping->host;
	ssize_t ret;

	inode_lock(inode);
	ret = generic_write_checks(iocb, from);
	if (ret > 0)
		ret = __generic_file_write_iter(iocb, from);
	inode_unlock(inode);

	if (ret > 0)
		ret = generic_write_sync(iocb, ret);  //最终调用f_op->fsync
	return ret;
}
EXPORT_SYMBOL(generic_file_write_iter);

// 
ssize_t __generic_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct address_space *mapping = file->f_mapping;
	struct inode 	*inode = mapping->host;
	ssize_t		written = 0;
	ssize_t		err;
	ssize_t		status;

	/* We can write back this queue in page reclaim */
	current->backing_dev_info = inode_to_bdi(inode);
	err = file_remove_privs(file);
	if (err)
		goto out;

	err = file_update_time(file);
	if (err)
		goto out;

	if (iocb->ki_flags & IOCB_DIRECT) {
		loff_t pos, endbyte;

		written = generic_file_direct_write(iocb, from);
		// 写操作失败，iov_iter_count返回未处理的数据长度，IS_DAX确定inode是否为direct access
		if (written < 0 || !iov_iter_count(from) || IS_DAX(inode))
			goto out;
		
		status = generic_perform_write(file, from, pos = iocb->ki_pos);
		
		if (unlikely(status < 0)) {
			err = status;
			goto out;
		}
		
		endbyte = pos + status - 1;
		err = filemap_write_and_wait_range(mapping, pos, endbyte);
		if (err == 0) {
			iocb->ki_pos = endbyte + 1;
			written += status;
			invalidate_mapping_pages(mapping,
						 pos >> PAGE_SHIFT,
						 endbyte >> PAGE_SHIFT);
		} else {
			
		}
	} else {
		written = generic_perform_write(file, from, iocb->ki_pos);
		if (likely(written > 0))
			iocb->ki_pos += written;
	}
out:
	current->backing_dev_info = NULL;
	return written ? written : err;
}
EXPORT_SYMBOL(__generic_file_write_iter);

// generic_perform_write函数，执行真正的写操作
ssize_t generic_perform_write(struct file *file,
				struct iov_iter *i, loff_t pos)
{
	struct address_space *mapping = file->f_mapping;
	const struct address_space_operations *a_ops = mapping->a_ops;
	long status = 0;
    // 记录已经写入的字节数
	ssize_t written = 0;
	unsigned int flags = 0;

	do {
        // 页缓存中的页面
		struct page *page;
        // 页内偏移量
		unsigned long offset;	/* Offset into pagecache page */
        // 要写入页面的字节数
		unsigned long bytes;	/* Bytes to write to page */
        // 从用户空间复制到页面的字节数
		size_t copied;		/* Bytes copied from user */
		void *fsdata = NULL;

		offset = (pos & (PAGE_SIZE - 1));
		bytes = min_t(unsigned long, PAGE_SIZE - offset,
						iov_iter_count(i));

again:
		/*
		 * Bring in the user page that we will copy from _first_.
		 * Otherwise there's a nasty deadlock on copying from the
		 * same page as we're writing to, without it being marked
		 * up-to-date.
		 */
		if (unlikely(fault_in_iov_iter_readable(i, bytes))) {
			status = -EFAULT;
			break;
		}

		if (fatal_signal_pending(current)) {
			status = -EINTR;
			break;
		}
		// 准备页面进行写操作
		status = a_ops->write_begin(file, mapping, pos, bytes, flags,
						&page, &fsdata);
		if (unlikely(status < 0))
			break;

		if (mapping_writably_mapped(mapping))
			flush_dcache_page(page);

		copied = copy_page_from_iter_atomic(page, offset, bytes, i);
		flush_dcache_page(page);

		status = a_ops->write_end(file, mapping, pos, bytes, copied,
						page, fsdata);
		if (unlikely(status != copied)) {
			iov_iter_revert(i, copied - max(status, 0L));
			if (unlikely(status < 0))
				break;
		}
		cond_resched();

		if (unlikely(status == 0)) {
			/*
			 * A short copy made ->write_end() reject the
			 * thing entirely.  Might be memory poisoning
			 * halfway through, might be a race with munmap,
			 * might be severe memory pressure.
			 */
			if (copied)
				bytes = copied;
			goto again;
		}
		pos += status;
		written += status;
		// 脏页适当地写回磁盘
		balance_dirty_pages_ratelimited(mapping);
	} while (iov_iter_count(i));

	return written ? written : status;
}
EXPORT_SYMBOL(generic_perform_write);
```



## read

```c
// read全过程
// 磁盘文件以页面呈现
struct address_space {
	struct inode		*host; // 文件相关的inode
	struct xarray		i_pages;
	struct rw_semaphore	invalidate_lock;
	gfp_t			gfp_mask;
	atomic_t		i_mmap_writable;
#ifdef CONFIG_READ_ONLY_THP_FOR_FS
	/* number of thp, only for non-shmem files */
	atomic_t		nr_thps;
#endif
	struct rb_root_cached	i_mmap;
	struct rw_semaphore	i_mmap_rwsem;
	unsigned long		nrpages;
	pgoff_t			writeback_index;
	const struct address_space_operations *a_ops; //操作函数
	unsigned long		flags;
	errseq_t		wb_err;
	spinlock_t		private_lock;
	struct list_head	private_list;
	void			*private_data;
} __attribute__((aligned(sizeof(long)))) __randomize_layout;
```

总体流程：

由于page cache的存在， read 并不是直接文件中读取， 而是从page cache中读，那么整体流程大概是： 如果page cache存在， 则直接从page cache中读取， 如果不存在， 则将文件内容先读到page cache中， 再copy给用户。



```c
// fs/read_write.c
// linux/file.h fd
struct fd {
	struct file *file;
	unsigned int flags;
};

ssize_t ksys_read(unsigned int fd, char __user *buf, size_t count)
{
	struct fd f = fdget_pos(fd);
	ssize_t ret = -EBADF;

	if (f.file) {
		loff_t pos, *ppos = file_ppos(f.file);
		if (ppos) {
			pos = *ppos;
			ppos = &pos;
		}
		ret = vfs_read(f.file, buf, count, ppos);
		if (ret >= 0 && ppos)
			f.file->f_pos = pos;
		fdput_pos(f);
	}
	return ret;
}

SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count)
{
	return ksys_read(fd, buf, count);
}

ssize_t vfs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
	ssize_t ret;

	if (!(file->f_mode & FMODE_READ))
		return -EBADF;
	if (!(file->f_mode & FMODE_CAN_READ))
		return -EINVAL;
	if (unlikely(!access_ok(buf, count)))
		return -EFAULT;

	ret = rw_verify_area(READ, file, pos, count);
	if (ret)
		return ret;
	if (count > MAX_RW_COUNT)
		count =  MAX_RW_COUNT;

	if (file->f_op->read)
		ret = file->f_op->read(file, buf, count, pos);
	else if (file->f_op->read_iter)
		ret = new_sync_read(file, buf, count, pos);
	else
		ret = -EINVAL;
	if (ret > 0) {
		fsnotify_access(file);
		add_rchar(current, ret);
	}
	inc_syscr(current);
	return ret;
}

static ssize_t new_sync_read(struct file *filp, char __user *buf, size_t len, loff_t *ppos)
{
	struct iovec iov = { .iov_base = buf, .iov_len = len };
	struct kiocb kiocb;
	struct iov_iter iter;
	ssize_t ret;

	init_sync_kiocb(&kiocb, filp);
	kiocb.ki_pos = (ppos ? *ppos : 0);
	iov_iter_init(&iter, READ, &iov, 1, len);

	ret = call_read_iter(filp, &kiocb, &iter);
	BUG_ON(ret == -EIOCBQUEUED);
	if (ppos)
		*ppos = kiocb.ki_pos;
	return ret;
}


// call_read_iter
// linux/fs.h
static inline ssize_t call_read_iter(struct file *file, struct kiocb *kio,
				     struct iov_iter *iter)
{
	return file->f_op->read_iter(kio, iter);
}

// read_iter
ssize_t
generic_file_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	size_t count = iov_iter_count(iter);
	ssize_t retval = 0;

	if (!count)
		return 0; /* skip atime */

	if (iocb->ki_flags & IOCB_DIRECT) {
		struct file *file = iocb->ki_filp;
		struct address_space *mapping = file->f_mapping;
		struct inode *inode = mapping->host;
		loff_t size;

		size = i_size_read(inode);
		if (iocb->ki_flags & IOCB_NOWAIT) {
			if (filemap_range_needs_writeback(mapping, iocb->ki_pos,
						iocb->ki_pos + count - 1))
				return -EAGAIN;
		} else {
			retval = filemap_write_and_wait_range(mapping,
						iocb->ki_pos,
					        iocb->ki_pos + count - 1);
			if (retval < 0)
				return retval;
		}

		file_accessed(file);

		retval = mapping->a_ops->direct_IO(iocb, iter);
		if (retval >= 0) {
			iocb->ki_pos += retval;
			count -= retval;
		}
		if (retval != -EIOCBQUEUED)
			iov_iter_revert(iter, count - iov_iter_count(iter));

		/*
		 * Btrfs can have a short DIO read if we encounter
		 * compressed extents, so if there was an error, or if
		 * we've already read everything we wanted to, or if
		 * there was a short read because we hit EOF, go ahead
		 * and return.  Otherwise fallthrough to buffered io for
		 * the rest of the read.  Buffered reads will not work for
		 * DAX files, so don't bother trying.
		 */
		if (retval < 0 || !count || iocb->ki_pos >= size ||
		    IS_DAX(inode))
			return retval;
	}

	return filemap_read(iocb, iter, retval);
}
EXPORT_SYMBOL(generic_file_read_iter);

ssize_t filemap_read(struct kiocb *iocb, struct iov_iter *iter,
		ssize_t already_read)
{
	struct file *filp = iocb->ki_filp;
	struct file_ra_state *ra = &filp->f_ra;
	struct address_space *mapping = filp->f_mapping;
	struct inode *inode = mapping->host;
	struct pagevec pvec;
	int i, error = 0;
	bool writably_mapped;
	loff_t isize, end_offset;
	if (unlikely(iocb->ki_pos >= inode->i_sb->s_maxbytes))
		return 0;
	if (unlikely(!iov_iter_count(iter)))
		return 0;
	iov_iter_truncate(iter, inode->i_sb->s_maxbytes);
	pagevec_init(&pvec);

	do {
		cond_resched();

		if ((iocb->ki_flags & IOCB_WAITQ) && already_read)
			iocb->ki_flags |= IOCB_NOWAIT;

		error = filemap_get_pages(iocb, iter, &pvec);
		if (error < 0)
			break;
		isize = i_size_read(inode);
		if (unlikely(iocb->ki_pos >= isize))
			goto put_pages;
		end_offset = min_t(loff_t, isize, iocb->ki_pos + iter->count);

		writably_mapped = mapping_writably_mapped(mapping);

		if (iocb->ki_pos >> PAGE_SHIFT !=
		    ra->prev_pos >> PAGE_SHIFT)
			mark_page_accessed(pvec.pages[0]);

		for (i = 0; i < pagevec_count(&pvec); i++) {
			struct page *page = pvec.pages[i];
			size_t page_size = thp_size(page);
			size_t offset = iocb->ki_pos & (page_size - 1);
			size_t bytes = min_t(loff_t, end_offset - iocb->ki_pos,
					     page_size - offset);
			size_t copied;

			if (end_offset < page_offset(page))
				break;
			if (i > 0)
				mark_page_accessed(page);
			if (writably_mapped) {
				int j;
				for (j = 0; j < thp_nr_pages(page); j++)
					flush_dcache_page(page + j);
			}
			copied = copy_page_to_iter(page, offset, bytes, iter);
			already_read += copied;
			iocb->ki_pos += copied;
			ra->prev_pos = iocb->ki_pos;

			if (copied < bytes) {
				error = -EFAULT;
				break;
			}
		}
put_pages:
		for (i = 0; i < pagevec_count(&pvec); i++)
			put_page(pvec.pages[i]);
		pagevec_reinit(&pvec);
	} while (iov_iter_count(iter) && iocb->ki_pos < isize && !error);
	file_accessed(filp);
	return already_read ? already_read : error;
}
EXPORT_SYMBOL_GPL(filemap_read);

// 预读会调用readpage函数，里面的mpage_readpage函数便是把磁盘块的内容读到page cache，其中主要调用do_mpage_readpage函数
static struct bio *do_mpage_readpage(struct mpage_readpage_args *args)
{
	struct page *page = args->page;
	struct inode *inode = page->mapping->host;
	const unsigned blkbits = inode->i_blkbits;
	const unsigned blocks_per_page = PAGE_SIZE >> blkbits;
	const unsigned blocksize = 1 << blkbits;
	struct buffer_head *map_bh = &args->map_bh;
	sector_t block_in_file;
	sector_t last_block;
	sector_t last_block_in_file;
	sector_t blocks[MAX_BUF_PER_PAGE];
	unsigned page_block;
	unsigned first_hole = blocks_per_page;
	struct block_device *bdev = NULL;
	int length;
	int fully_mapped = 1;
	int op_flags;
	unsigned nblocks;
	unsigned relative_block;
	gfp_t gfp;

	if (args->is_readahead) {
		op_flags = REQ_RAHEAD;
		gfp = readahead_gfp_mask(page->mapping);
	} else {
		op_flags = 0;
		gfp = mapping_gfp_constraint(page->mapping, GFP_KERNEL);
	}

	if (page_has_buffers(page))
		goto confused;

	block_in_file = (sector_t)page->index << (PAGE_SHIFT - blkbits);
	last_block = block_in_file + args->nr_pages * blocks_per_page;
	last_block_in_file = (i_size_read(inode) + blocksize - 1) >> blkbits;
	if (last_block > last_block_in_file)
		last_block = last_block_in_file;
	page_block = 0;

	/*
	 * Map blocks using the result from the previous get_blocks call first.
	 */
	nblocks = map_bh->b_size >> blkbits;
	if (buffer_mapped(map_bh) &&
			block_in_file > args->first_logical_block &&
			block_in_file < (args->first_logical_block + nblocks)) {
		unsigned map_offset = block_in_file - args->first_logical_block;
		unsigned last = nblocks - map_offset;

		for (relative_block = 0; ; relative_block++) {
			if (relative_block == last) {
				clear_buffer_mapped(map_bh);
				break;
			}
			if (page_block == blocks_per_page)
				break;
			blocks[page_block] = map_bh->b_blocknr + map_offset +
						relative_block;
			page_block++;
			block_in_file++;
		}
		bdev = map_bh->b_bdev;
	}

	/*
	 * Then do more get_blocks calls until we are done with this page.
	 */
	map_bh->b_page = page;
	while (page_block < blocks_per_page) {
		map_bh->b_state = 0;
		map_bh->b_size = 0;

		if (block_in_file < last_block) {
			map_bh->b_size = (last_block-block_in_file) << blkbits;
			if (args->get_block(inode, block_in_file, map_bh, 0))
				goto confused;
			args->first_logical_block = block_in_file;
		}

		if (!buffer_mapped(map_bh)) {
			fully_mapped = 0;
			if (first_hole == blocks_per_page)
				first_hole = page_block;
			page_block++;
			block_in_file++;
			continue;
		}

		/* some filesystems will copy data into the page during
		 * the get_block call, in which case we don't want to
		 * read it again.  map_buffer_to_page copies the data
		 * we just collected from get_block into the page's buffers
		 * so readpage doesn't have to repeat the get_block call
		 */
		if (buffer_uptodate(map_bh)) {
			map_buffer_to_page(page, map_bh, page_block);
			goto confused;
		}
	
		if (first_hole != blocks_per_page)
			goto confused;		/* hole -> non-hole */

		/* Contiguous blocks? */
		if (page_block && blocks[page_block-1] != map_bh->b_blocknr-1)
			goto confused;
		nblocks = map_bh->b_size >> blkbits;
		for (relative_block = 0; ; relative_block++) {
			if (relative_block == nblocks) {
				clear_buffer_mapped(map_bh);
				break;
			} else if (page_block == blocks_per_page)
				break;
			blocks[page_block] = map_bh->b_blocknr+relative_block;
			page_block++;
			block_in_file++;
		}
		bdev = map_bh->b_bdev;
	}

	if (first_hole != blocks_per_page) {
		zero_user_segment(page, first_hole << blkbits, PAGE_SIZE);
		if (first_hole == 0) {
			SetPageUptodate(page);
			unlock_page(page);
			goto out;
		}
	} else if (fully_mapped) {
		SetPageMappedToDisk(page);
	}

	if (fully_mapped && blocks_per_page == 1 && !PageUptodate(page) &&
	    cleancache_get_page(page) == 0) {
		SetPageUptodate(page);
		goto confused;
	}

	/*
	 * This page will go to BIO.  Do we need to send this BIO off first?
	 */
	if (args->bio && (args->last_block_in_bio != blocks[0] - 1))
		args->bio = mpage_bio_submit(REQ_OP_READ, op_flags, args->bio);

alloc_new:
	if (args->bio == NULL) {
		if (first_hole == blocks_per_page) {
			if (!bdev_read_page(bdev, blocks[0] << (blkbits - 9),
								page))
				goto out;
		}
		args->bio = mpage_alloc(bdev, blocks[0] << (blkbits - 9),
					bio_max_segs(args->nr_pages), gfp);
		if (args->bio == NULL)
			goto confused;
	}

	length = first_hole << blkbits;
	if (bio_add_page(args->bio, page, length, 0) < length) {
		args->bio = mpage_bio_submit(REQ_OP_READ, op_flags, args->bio);
		goto alloc_new;
	}

	relative_block = block_in_file - args->first_logical_block;
	nblocks = map_bh->b_size >> blkbits;
	if ((buffer_boundary(map_bh) && relative_block == nblocks) ||
	    (first_hole != blocks_per_page))
		args->bio = mpage_bio_submit(REQ_OP_READ, op_flags, args->bio);
	else
		args->last_block_in_bio = blocks[blocks_per_page - 1];
out:
	return args->bio;

confused:
	if (args->bio)
		args->bio = mpage_bio_submit(REQ_OP_READ, op_flags, args->bio);
	if (!PageUptodate(page))
		block_read_full_page(page, args->get_block);
	else
		unlock_page(page);
	goto out;
}
// block_read_full_page函数通过buffer head的方式读取


//writepage函数为将page cache的东西写入磁盘
```



## mount

```c
// fs/mount.h 表示根文件系统中的挂载点
struct mountpoint {
	struct hlist_node m_hash;  // 添加至全局hash散列表
	struct dentry *m_dentry;	//挂载点dentry实例指针
	struct hlist_head m_list;
	int m_count;  //挂载点挂载操作的次数
};

// mount结构体表示一次挂载操作
struct mount {
	struct hlist_node mnt_hash;//散列链表节点成员
	struct mount *mnt_parent; 
	struct dentry *mnt_mountpoint;//挂载点dentry实例
	struct vfsmount mnt;
	union {
		struct rcu_head mnt_rcu;
		struct llist_node mnt_llist;
	};
    
struct vfsmount {
	struct dentry *mnt_root;	     //指向挂载文件系统根目录项dentry实例
	struct super_block *mnt_sb;	   //指向文件系统超级块实例
	int mnt_flags;                 //内核内部使用的挂载标记
	struct user_namespace *mnt_userns;
} __randomize_layout;
```

