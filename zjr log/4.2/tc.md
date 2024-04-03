# 总流程分析及项目开发

## revofs

### 总的磁盘布局结构

| super | inode_store | inode_bitmap | block_bitmap | blocks  data |
| ----- | ----------- | ------------ | ------------ | ------------ |

### super block 超级块

超级块磁盘布局：

| magic                  |
| ---------------------- |
| **nr_blocks**          |
| **nr_inodes**          |
| **nr_istore_blocks**   |
| **nr_ifree_blocks**    |
| **nr_bfree_blocks**    |
| **nr_free_inodes**     |
| **nr_free_blocks**     |
| **char padding[4064]** |

前面的共占8*4 = 32字节，然后填充4064字节刚好占一个磁盘块



超级块内存布局：

在挂载时通过revofs_fill_super函数来填充内存的超级块对象**struct super_block *sb**，首先磁盘中超级块的数据会读入一个**revofs_sb_info**结构体中，这个结构体仅仅是比磁盘中的数据布局多了两个freemap，只需要将freemap的内容读磁盘进行填充即可。



然后把这个结构体接在sb->s_fs_info中即可。

此外对**sb**的其他填充涉及到如下字段：

- s_magic 文件系统幻数
- s_blocksize 一个磁盘块的字节大小
- s_maxbytes  文件大小上限
- s_op 即super_operations



### inode 索引块

inode**磁盘**布局：

```c
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
```

磁盘布局与上述结构体中的数据类似，一个磁盘块中有多个inode。



inode**内存**布局：

从磁盘中我们读取的inode在内存中进行了两次封装，一种是封装为linux中自带的inode结构体，接着会对linux自带的inode结构体进行进一步封装为revofs_inode_info结构。

```c
struct revofs_inode_info {
    uint32_t ei_block;  /* Block with list of extents for this file */
    char i_data[32];
    struct inode vfs_inode;
};// 对linux中自带的inode填充后进一步封装为revofs_inode_info结构体
```



#### 从磁盘读入到内存中具体的填充字段

inode.c中的revofs_iget函数作用即为从磁盘中获取ino对应的inode，并在内存中进行封装。

```c
...
    cinode = (struct revofs_inode *) bh->b_data;
    cinode += inode_shift;

    inode->i_ino = ino;
    inode->i_sb = sb;
    inode->i_op = &revofs_inode_ops;
    // change to main machine
    inode->i_mode = le32_to_cpu(cinode->i_mode);
    // usr id
    i_uid_write(inode, le32_to_cpu(cinode->i_uid));
    // group id
    i_gid_write(inode, le32_to_cpu(cinode->i_gid));
    inode->i_size = le32_to_cpu(cinode->i_size);
    inode->i_ctime.tv_sec = (time64_t) le32_to_cpu(cinode->i_ctime);
    inode->i_ctime.tv_nsec = 0;
    inode->i_atime.tv_sec = (time64_t) le32_to_cpu(cinode->i_atime);
    inode->i_atime.tv_nsec = 0;
    inode->i_mtime.tv_sec = (time64_t) le32_to_cpu(cinode->i_mtime);
    inode->i_mtime.tv_nsec = 0;
    inode->i_blocks = le32_to_cpu(cinode->i_blocks);
    set_nlink(inode, le32_to_cpu(cinode->i_nlink));

    // i_fop 缺省的索引节点操作 file_operation
    if (S_ISDIR(inode->i_mode)) {
        ci->ei_block = le32_to_cpu(cinode->ei_block);
        inode->i_fop = &revofs_dir_ops;
    } else if (S_ISREG(inode->i_mode)) {
        ci->ei_block = le32_to_cpu(cinode->ei_block);
        inode->i_fop = &revofs_file_ops;
        inode->i_mapping->a_ops = &revofs_aops;
    } else if (S_ISLNK(inode->i_mode)) {
        strncpy(ci->i_data, cinode->i_data, sizeof(ci->i_data));
        inode->i_link = ci->i_data;
        inode->i_op = &symlink_inode_ops;
    }
...
```

从上述可以看出从磁盘块读取的inode内容首先由bufferhead bh接收，并将其转化为结构体类型，然后通过此revofs_inode结构对inode中的以下字段进行了赋值：

- i_ino inode块号
- i_sb 内存超级块结构
- i_op 对应的inode_operations 注意如果是符号连接的话需要将其替换为专门编写的符号连接操作
- i_mode 标识此文件是什么类型：
  - DIR
  - REG FILE
  - SLINK
- i_size 以字节为单位的文件大小
- i_ctime 最后改变时间
- i_atime 最后访问时间
- i_mtime 最后修改时间
- i_blocks 文件的所占磁盘块数
- i_nlink 硬链接数
- i_fop 根据上述i_mode选取对应的file_operations进行赋值
- i_mapping->a_ops 涉及到页缓存的操作
- i_link 符号连接的符号



此外此inode所属的revofs_inode_info填充ei_block，表示其扩展块号是哪个。如果inode的i_mode标识它是一个符号连接的话，还得对其i_data进行赋值



#### 磁盘中inode索引文件的逻辑

前面对磁盘中的inode结构进行了分析说明，如下：

```c
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
```

其中**ei_block**是扩展块号，其中扩展块的结构如下：

| nr_files                                      |
| --------------------------------------------- |
| **revofs_extent extents[REVOFS_MAX_EXTENTS]** |

```c
struct revofs_extent {
    uint32_t ee_block; /* first logical block extent covers */ // one extent first logical
    uint32_t ee_len;   /* number of blocks covered by extent */
    uint32_t ee_start; /* first physical block extent covers */
};
```

其中revofs_extent的结构如上，`ee_block`表示的是本extent区域开头的逻辑块号，`ee_len`标识本extent区域的所占磁盘块的数目，本文件系统默认一个extent是八个磁盘块，`ee_start`是本extent区域开头的真实物理块号。



为啥需要extent区域：可以实现大文件的创建和操作分配，因为extent区域表示的是连续的八个磁盘块的空间，可以实现大文件的创建，并且由于是连续的提高了磁盘访问效率。

![1](1.jpg)



#### 磁盘block中存储的目录项结构

| inode number     |
| ---------------- |
| **filename**     |
| **inode number** |
| **filename**     |
| ...              |



### 文件系统总逻辑

#### 文件系统注册

```c
//fs/filesystems.c
// 内核中已经注册了的文件系统串联的链表
static struct file_system_type *file_systems;

int register_filesystem(struct file_system_type * fs)
{
	int res = 0;
	struct file_system_type ** p;

	if (fs->parameters &&
	    !fs_validate_description(fs->name, fs->parameters))
		return -EINVAL;

	BUG_ON(strchr(fs->name, '.'));
	if (fs->next)
		return -EBUSY;
	write_lock(&file_systems_lock);
	p = find_filesystem(fs->name, strlen(fs->name));
	if (*p)
		res = -EBUSY;
	else
		*p = fs;
	write_unlock(&file_systems_lock);
	return res;
}
```

内核中文件系统的注册其实很简单，就是将自己写好的file_system_type结构加入到内核维护的相关链表中。当我们注册一个文件系统时，会依据文件系统的名字来查看链表中是否存在，如果存在就不再重复注册，否则会加入到链表末尾。



#### 格式化磁盘

将磁盘格式化为我们文件系统的总体磁盘布局结构，这个时候便需要我们编写格式化程序。revofs中便是在mkfs.c中实现了格式化磁盘，在main函数中，主要是以下步骤：

1. 用open系统调用打开设备文件，然后准备执行写操作；
2. 在内存中封装好写入磁盘的超级快内容，写超级块；
3. 写inode_store。这里只对第0个inode进行了初始化，表示其是根目录，并且对其ei_block块号分配为第一个数据块；
4. 写inode_bitmap。这里只将第0个inode的置为0，表示使用。其余的全部为未使用；
5. 写blocks_bitmap。在这里明显我们首先计算已经使用过的磁盘块，明显是super，inode_store,inode_bitmap,block_bitmap，还有root inode的ei_block。这些我们都要初始化为使用，即置0；
6. 对数据块无操作。



#### 挂载 mount

挂载操作的最后其实就是调用的file_system_type中的mount函数。

如果我们在命令行输入这么一段话：

**sudo mount -t revofs /dev/loop7 /mnt/test**

那么revofs便是我们的挂载的文件系统类型，/dev/loop7为挂载的设备名，/mnt/test为挂载点。一旦执行触发系统调用：

```c
// fs/namespace.c
SYSCALL_DEFINE5(mount, char __user *, dev_name, char __user *, dir_name,
		char __user *, type, unsigned long, flags, void __user *, data)
{
	int ret;
	char *kernel_type;
	char *kernel_dev;
	void *options;
	// 拷贝文件系统类型名到内核空间
	kernel_type = copy_mount_string(type);
	ret = PTR_ERR(kernel_type);
	if (IS_ERR(kernel_type))
		goto out_type;
	// 挂载设备路径名拷贝
	kernel_dev = copy_mount_string(dev_name);
	ret = PTR_ERR(kernel_dev);
	if (IS_ERR(kernel_dev))
		goto out_dev;
	// 挂载选项拷贝
	options = copy_mount_options(data);
	ret = PTR_ERR(options);
	if (IS_ERR(options))
		goto out_data;
	// 开启挂载 dir_name是挂载点目录
	ret = do_mount(kernel_dev, dir_name, kernel_type, flags, options);

	kfree(options);
out_data:
	kfree(kernel_dev);
out_dev:
	kfree(kernel_type);
out_type:
	return ret;
}
```

接下来进入do_mount函数



```c
// include/linux/path.c
struct path {
	struct vfsmount *mnt;	
	struct dentry *dentry; //挂载点目录dentry实例
} __randomize_layout;

long do_mount(const char *dev_name, const char __user *dir_name,
		const char *type_page, unsigned long flags, void *data_page)
{
	struct path path;
	int ret;
	// 把挂载点解析成path路径结构
	ret = user_path_at(AT_FDCWD, dir_name, LOOKUP_FOLLOW, &path);
	if (ret)
		return ret;
	ret = path_mount(dev_name, &path, type_page, flags, data_page);
	path_put(&path);
	return ret;
}

// path_mount中最后调用核心是do_new_mount
static int do_new_mount(struct path *path, const char *fstype, int sb_flags,
			int mnt_flags, const char *name, void *data)
{
	struct file_system_type *type;
	struct fs_context *fc;
	const char *subtype = NULL;
	int err = 0;

	if (!fstype)
		return -EINVAL;
	// 由文件系统名获取file_system_type实例
	type = get_fs_type(fstype);
	if (!type)
		return -ENODEV;

	if (type->fs_flags & FS_HAS_SUBTYPE) {
		subtype = strchr(fstype, '.');
		if (subtype) {
			subtype++;
			if (!*subtype) {
				put_filesystem(type);
				return -EINVAL;
			}
		}
	}
	// 创建fs_context结构体
	fc = fs_context_for_mount(type, sb_flags);
	put_filesystem(type);
	if (IS_ERR(fc))
		return PTR_ERR(fc);

	if (subtype)
		err = vfs_parse_fs_string(fc, "subtype",
					  subtype, strlen(subtype));
	if (!err && name)
		err = vfs_parse_fs_string(fc, "source", name, strlen(name));
	if (!err)
		err = parse_monolithic_mount_data(fc, data);
	if (!err && !mount_capable(fc))
		err = -EPERM;
	if (!err)
		err = vfs_get_tree(fc);
	if (!err)
        // 执行新的挂载
		err = do_new_mount_fc(fc, path, mnt_flags);

	put_fs_context(fc);
	return err;
}

// do_new_mount_fc
static int do_new_mount_fc(struct fs_context *fc, struct path *mountpoint,
			   unsigned int mnt_flags)
{
	struct vfsmount *mnt;
	......
	// 由fs_context创建vfsmount
	mnt = vfs_create_mount(fc);
	
	......
	error = do_add_mount(real_mount(mnt), mp, mountpoint, mnt_flags);
	......
	return error;
}
```



现在比较**vfsmount**和**fs_context**的结构：

```c
struct fs_context {
......
    struct dentry		*root;		/* The root and superblock */
......
};

struct vfsmount {
    struct dentry *mnt_root;	/* root of the mounted tree */
    struct super_block *mnt_sb;	/* pointer to superblock */
    int mnt_flags;
} __randomize_layout;

// mount结构 每个挂载的文件系统都会创建
struct mount {
	struct hlist_node mnt_hash;
	struct mount *mnt_parent;
	struct dentry *mnt_mountpoint;
	struct vfsmount mnt;
	union {
		struct rcu_head mnt_rcu;
		struct llist_node mnt_llist;
	};
...
    
	struct list_head mnt_mounts;	/* list of children, anchored here */
	struct list_head mnt_child;	/* and going through their mnt_child */
	struct list_head mnt_instance;	/* mount instance on sb->s_mounts */
	const char *mnt_devname;	/* Name of device e.g. /dev/dsk/hda1 */
	struct list_head mnt_list;
    
...
} __randomize_layout;

// fs/mount.h 表示根文件系统中的挂载点
struct mountpoint {
	struct hlist_node m_hash;  // 添加至全局hash散列表
	struct dentry *m_dentry;	//挂载点dentry实例指针
	struct hlist_head m_list;
	int m_count;  //挂载点挂载操作的次数
};
```





继续对上述do_new_mount函数分析：

1. **type = get_fs_type(fstype)**。根据`fstype`找到对应的`file_system_type`结构体；

2. **fc = fs_context_for_mount(type, sb_flags)**。这里面，会调用文件系统自定义的init_fs_context回调； 如果没有定义fc->fs_type->init_fs_context， 则会调用**legacy_init_fs_context**初始化, 这里fc->ops = &legacy_fs_context_ops， 其中legacy_get_tree会调用fc->fs_type->mount；

   ```c
   const struct fs_context_operations legacy_fs_context_ops = {
   	.free			= legacy_fs_context_free,
   	.dup			= legacy_fs_context_dup,
   	.parse_param		= legacy_parse_param,
   	.parse_monolithic	= legacy_parse_monolithic,
   	.get_tree		= legacy_get_tree,
   	.reconfigure		= legacy_reconfigure,
   };
   ```

   

3. 调用`vfs_get_tree`，这里面会调用**fc->ops->get_tree**。如果按照上述调用，那么会调用**legacy_get_tree**函数，里面会调用我们自己写的mount函数。在我们自己写的mount函数中我们执行了填充超级块，初始化根目录inode的操作等

   ```c
   static int legacy_get_tree(struct fs_context *fc)
   {
   	struct legacy_fs_context *ctx = fc->fs_private;
   	struct super_block *sb;
   	struct dentry *root;
   	// dentry
   	root = fc->fs_type->mount(fc->fs_type, fc->sb_flags,
   				      fc->source, ctx->legacy_data);
   	if (IS_ERR(root))
   		return PTR_ERR(root);
   	// 获取超级块
   	sb = root->d_sb;
   	BUG_ON(!sb);
   	// 获取根目录
   	fc->root = root;
   	return 0;
   }
   ```

   

4. `vfs_get_tree`函数执行完后会执行`do_new_mount_fc`函数。如下：

   ```c
   static int do_new_mount_fc(struct fs_context *fc, struct path *mountpoint,
   			   unsigned int mnt_flags)
   {
   	struct vfsmount *mnt;
   	struct mountpoint *mp;
   	struct super_block *sb = fc->root->d_sb;
   	...
   
   	mnt = vfs_create_mount(fc);
   	...
   	error = do_add_mount(real_mount(mnt), mp, mountpoint, mnt_flags);
   	...
   	return error;
   }
   ```

   每个挂载的文件系统都会创建**mount**结构来表示挂载的信息，在**vfs_create_mount**函数中，会创建mount结构，然后依据fs_context来对mount结构信息进行填充并且对vfsmnt结构进行初始化和填充。这样最后其实mount结构体便和文件系统建立了联系。do_add_mount进一步创建新的挂载实例关联到系统。



#### 读 read

当要读文件时，发生read系统调用，其实最后关联如下：

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
```

其实执行上述系统调用，最后转到ksys_read中，在这个里面会获取文件偏移指针，然后调用vfs_read函数。最后更新文件偏移指针。



vfs_read函数如下：

```c
ssize_t vfs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
	...

	if (file->f_op->read)
		ret = file->f_op->read(file, buf, count, pos);
	else if (file->f_op->read_iter)
		ret = new_sync_read(file, buf, count, pos);
	else
		ret = -EINVAL;
	...
	return ret;
}
```

如果我们定义的file_operation中有read函数，那么会优先调用read函数。否则如果read_iter函数存在，则会调用new_sync_read函数。现在一般使用page cache的都会转向调用new_sync_read函数。



new_sync_read函数如下：

```c
static ssize_t new_sync_read(struct file *filp, char __user *buf, size_t len, loff_t *ppos)
{
    // 用于初始化一段内存区域
	struct iovec iov = { .iov_base = buf, .iov_len = len };
    // kernel 每一次读写都会对应一个kiocb
	struct kiocb kiocb;
    // iter 用于数据在内核空间和用户空间之间的迭代
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
```

上述重点是调用`call_read_iter`函数，他会转向调用我们自己编写的`file_operations`中的`read_iter`函数。如果我们设置的这个为`generic_file_read_iter`函数，最后会转向filemap_read函数。



filemap_read函数作业便是从page cache获取与文件相关的连续页，然后便可以以页的形式读入数据。

```c
// mm/filemap.c
ssize_t filemap_read(struct kiocb *iocb, struct iov_iter *iter,
		ssize_t already_read)
{
	...
}
```



当我们从page cache中获取文件数据的时候，会有预读的过程。也就是我们会先把磁盘中文件的数据读入到page cache中组装成页，这个时候需要调用address_space_operations函数中的**readpage**函数。



本次revofs里面的readpage函数如下：

```c
// 从文件中读取一个或多个页的内容到page中
static int revofs_readpage(struct file *file, struct page *page)
{
    return mpage_readpage(page, revofs_file_get_block);
}
// mpage_readpage的核心最后是调用do_mpage_readpage函数
```

**do_mpage_readpage**的整体逻辑就是， 尽量通过bio的方式去读取连续的sector， 如果不行， 就转而通过buffer_head的方式一个sector一个sector去读。其实也就是bio是用于磁盘连续磁盘块的读取，效率高；但是如果不连续的话只有用bufferhead一个个磁盘块的读。



#### 写 write

当发起write系统调用后，其实是转进了ksys_write函数。

```c
SYSCALL_DEFINE3(write, unsigned int, fd, const char __user *, buf,
		size_t, count)
{
	return ksys_write(fd, buf, count);
}

ssize_t ksys_write(unsigned int fd, const char __user *buf, size_t count)
{
	struct fd f = fdget_pos(fd);
	ssize_t ret = -EBADF;
	// 定位文件偏移指针
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
```



`vfs_write`层写函数如下：

```c
ssize_t vfs_write(struct file *file, const char __user *buf, size_t count, loff_t *pos)
{
	...
    // write 以及write_iter函数的选择
	if (file->f_op->write)
		ret = file->f_op->write(file, buf, count, pos);
	else if (file->f_op->write_iter)
		ret = new_sync_write(file, buf, count, pos);
	else
		ret = -EINVAL;
	...
	return ret;
}
```

和read一样，在这里会优先选择`file_operations`中的write函数来写，如果没有write函数，则会选用`write_iter`函数。



```c
// new_sync_write
static ssize_t new_sync_write(struct file *filp, const char __user *buf, size_t len, loff_t *ppos)
{
    ...
	ret = call_write_iter(filp, &kiocb, &iter);
	BUG_ON(ret == -EIOCBQUEUED);
	if (ret > 0 && ppos)
		*ppos = kiocb.ki_pos;
	...
}

// call_write_iter
static inline ssize_t call_write_iter(struct file *file, struct kiocb *kio,
				      struct iov_iter *iter)
{
	return file->f_op->write_iter(kio, iter);
}
```

本次revofs里面用的是**generic_file_write_iter**，这个又是与**page cache**相关的写函数：

```c
ssize_t generic_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file->f_mapping->host;
	ssize_t ret;

	inode_lock(inode);
	ret = generic_write_checks(iocb, from);
    // 写内容到page cache
	if (ret > 0)
		ret = __generic_file_write_iter(iocb, from);
	inode_unlock(inode);

	if (ret > 0)
		ret = generic_write_sync(iocb, ret);  //最终调用f_op->fsync
	return ret;
}
```



__generic_file_write_iter函数中又会调用generic_perform_write函数来执行真正的写操作，即把数据写到page cache的页面里面。

```c
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
		// 进行善后操作
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
```

在这个函数中调用了`write_begin`和`write_end`函数。



### operations

#### super_operations

revofs中实现如下：

```c
static struct super_operations revofs_super_ops = {
    .put_super = revofs_put_super,
    .alloc_inode = revofs_alloc_inode,
    .destroy_inode = revofs_destroy_inode,
    .write_inode = revofs_write_inode,
    .sync_fs = revofs_sync_fs,
    .statfs = revofs_statfs,
};
```

其中put_super，alloc_inode，destroy_inode均是内存层面进行的操作。

1. put_super。在卸载文件系统时会调用，卸载文件系统时会调用file_system_type中的函数kill_sb，在这里面会释放内存中的super block结构；
2. alloc_inode。在内存中分配一个inode结构
3. destroy_inode。在内存中释放一个inode结构
4. write_inode。将内存中的inode回写磁盘
5. sync_fs。回写超级块，bitmap等结构到磁盘
6. statfs。提取文件系统信息到stat结构。



#### inode_operations

```c
static const struct inode_operations revofs_inode_ops = {
    .lookup = revofs_lookup,
    .create = revofs_create,  // 创建文件时使用
    .unlink = revofs_unlink,
    .mkdir = revofs_mkdir,
    .rmdir = revofs_rmdir,
    .rename = revofs_rename,
    .link = revofs_link,
    .symlink = revofs_symlink,
};
```

1. lookup。这个是打开文件open时用到的，会依据目录项在指定目录下搜索得到目录项所指的inode。并将其与dentry相关联；
2. create。这个也在打开文件open时用到过。如果lookup失败，则会依据是否创建来创建相关的inode和目录项，彼此相关联；
3. unlink。文件无链接后，用这个方式删除文件；
4. rename。这个主要是用于文件的移植操作，inode关联；
5. mkdir。mkdir创建目录时会调用；
6. rmdir。删除目录；
7. link。创建硬连接；
8. symlink。符号连接i_link字段赋值。



#### file_operations

```c
const struct file_operations revofs_dir_ops = {
    .owner = THIS_MODULE,
    // ll ls命令会用到
    .iterate_shared = revofs_iterate,
};

const struct file_operations revofs_file_ops = {
    .llseek = generic_file_llseek, //文件中偏移量定位
    .owner = THIS_MODULE,
    .read_iter = generic_file_read_iter, //page cache读调用  
    .write_iter = generic_file_write_iter, // page cache写调用
    .fsync = generic_file_fsync,  //同步文件缓冲数据
};

// 文件系统与页缓存映射 执行函数
const struct address_space_operations revofs_aops = {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 19, 0)
    .readahead = revofs_readahead,
#else
     
    .readpage = revofs_readpage, // disk读取页到page cache
#endif
    .writepage = revofs_writepage, // page cache写页到disk
    .write_begin = revofs_write_begin, // 写前准备，包括一部分预读
    .write_end = revofs_write_end, //写后的善后工作
};

```



#### file_system_type

```c
static struct file_system_type revofs_file_system_type = {
    .owner = THIS_MODULE,
    .name = "revofs",
    .mount = revofs_mount, // mount时使用
    .kill_sb = revofs_kill_sb, // 卸载文件系统时使用
    .fs_flags = FS_REQUIRES_DEV,
    .next = NULL,
};
```



## 要实现的内容



