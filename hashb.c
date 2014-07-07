#include <linux/export.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/genhd.h>
#include <crypto/hash.h>
#include <linux/scatterlist.h>

#define SECTOR_SHIFT 9
#define SECTORS_PER_PAGE_SHIFT	(PAGE_SHIFT - SECTOR_SHIFT)

#define MULTIPLE (PAGE_SIZE >> SECTOR_SHIFT)
#define DEFAULT_DISKSIZE (32*1024*1024)
#define DIST_RANGE	4

#define SMT_INDEX_LENGTH	20	
#define SMT_SIZE		(1U << SMT_INDEX_LENGTH)
#define SMT_MASK		(SMT_SIZE - 1) 
#define SMT_INDEX(h)		(h & SMT_MASK)

#define R0	0
#define R1	262144
#define R2	524288
#define R3	786432
#define R4	1048576

static int hashb_major = 0;
static int max_num_devices = 2;

/* Module params (documentation at end) */
static unsigned int hashb_num_devices = 0;

struct hashb_stats {
	atomic_t num_reads;		
	atomic_t num_writes;	
	atomic_t chash_dist[DIST_RANGE];
	atomic_t ihash_dist[DIST_RANGE];
};

struct hashb{
	struct request_queue *queue;
	struct gendisk *disk;
	int init_done;
	/* Prevent concurrent execution of device init, reset and R/W request */
	struct rw_semaphore init_lock;
	struct hashb_stats stats;
};

static struct hashb *hashb_devices = NULL;

/*----------hashb_sysfs>----------*/
static void hashb_stats_init(struct hashb_stats *hashb_stats)
{	
	int i = 0;
	atomic_set(&hashb_stats->num_reads, 0);
	atomic_set(&hashb_stats->num_writes, 0);
	
	for (i = 0; i < DIST_RANGE; ++i) {
		atomic_set(&hashb_stats->chash_dist[i], 0);
		atomic_set(&hashb_stats->ihash_dist[i], 0);
	}
}

static struct hashb *dev_to_hashb(struct device *dev)
{
	int i;
	struct hashb *hashb = NULL;

	for (i = 0; i < hashb_num_devices; i++) {
		hashb = &hashb_devices[i];
		if (disk_to_dev(hashb->disk) == dev)
			break;
	}

	return hashb;
}

static ssize_t num_reads_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct hashb *hashb = dev_to_hashb(dev);

	return sprintf(buf, "%d\n",
		atomic_read(&hashb->stats.num_reads));
}

static ssize_t num_writes_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct hashb *hashb = dev_to_hashb(dev);

	return sprintf(buf, "%d\n",
		atomic_read(&hashb->stats.num_writes));
}


static ssize_t cR1_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct hashb *hashb = dev_to_hashb(dev);

	return sprintf(buf, "%d\n",
		atomic_read(&hashb->stats.chash_dist[0]));
}

static ssize_t cR2_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct hashb *hashb = dev_to_hashb(dev);

	return sprintf(buf, "%d\n",
		atomic_read(&hashb->stats.chash_dist[1]));
}

static ssize_t cR3_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct hashb *hashb = dev_to_hashb(dev);

	return sprintf(buf, "%d\n",
		atomic_read(&hashb->stats.chash_dist[2]));
}

static ssize_t cR4_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct hashb *hashb = dev_to_hashb(dev);

	return sprintf(buf, "%d\n",
		atomic_read(&hashb->stats.chash_dist[3]));
}

static ssize_t iR1_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct hashb *hashb = dev_to_hashb(dev);

	return sprintf(buf, "%d\n",
		atomic_read(&hashb->stats.ihash_dist[0]));
}

static ssize_t iR2_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct hashb *hashb = dev_to_hashb(dev);

	return sprintf(buf, "%d\n",
		atomic_read(&hashb->stats.ihash_dist[1]));
}

static ssize_t iR3_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct hashb *hashb = dev_to_hashb(dev);

	return sprintf(buf, "%d\n",
		atomic_read(&hashb->stats.ihash_dist[2]));
}

static ssize_t iR4_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct hashb *hashb = dev_to_hashb(dev);

	return sprintf(buf, "%d\n",
		atomic_read(&hashb->stats.ihash_dist[3]));
}

static DEVICE_ATTR(num_reads, S_IRUGO, num_reads_show, NULL);
static DEVICE_ATTR(num_writes, S_IRUGO, num_writes_show, NULL);
static DEVICE_ATTR(cR1, S_IRUGO, cR1_show, NULL);
static DEVICE_ATTR(cR2, S_IRUGO, cR2_show, NULL);
static DEVICE_ATTR(cR3, S_IRUGO, cR3_show, NULL);
static DEVICE_ATTR(cR4, S_IRUGO, cR4_show, NULL);
static DEVICE_ATTR(iR1, S_IRUGO, iR1_show, NULL);
static DEVICE_ATTR(iR2, S_IRUGO, iR2_show, NULL);
static DEVICE_ATTR(iR3, S_IRUGO, iR3_show, NULL);
static DEVICE_ATTR(iR4, S_IRUGO, iR4_show, NULL);

static struct attribute *hashb_disk_attrs[] = {
	&dev_attr_num_reads.attr,
	&dev_attr_num_writes.attr,
	&dev_attr_cR1.attr,
	&dev_attr_cR2.attr,
	&dev_attr_cR3.attr,
	&dev_attr_cR4.attr,
	&dev_attr_iR1.attr,
	&dev_attr_iR2.attr,
	&dev_attr_iR3.attr,
	&dev_attr_iR4.attr,
	NULL,
};

struct attribute_group hashb_disk_attr_group = {
	.attrs = hashb_disk_attrs,
};
/*----------<hashb_sysfs----------*/

static const struct block_device_operations hashb_devops = {
	.owner = THIS_MODULE
};


u64 trcd_hash (void *val, size_t len, u8 *result)
{
	u64 * v64p = val;
	u64 h64 = 0;
	u64 tail64 = 0;
	u8 * v8p, * tail8p = (u8*)& tail64;

	while (len>=8){
		h64 ^= *v64p;
		v64p++;
		len -= 8;
	};

	if (unlikely(len > 0)) {
		v8p = (u8*)v64p;
		for (;len>0;len--){
			*tail8p = *v8p;
			tail8p++;
			v8p++;
		}
		h64 ^= tail64;
	}
	(*(u64*)result) = h64;
	return h64;
}

static void sha1_hash(const void *data, size_t nbytes, u8 *result)
{
	struct scatterlist sg;
	struct crypto_hash *tfm;
	struct hash_desc desc;

	tfm = crypto_alloc_hash("sha1", 0, CRYPTO_ALG_ASYNC);

	if (IS_ERR(tfm)) {
		printk(KERN_ERR "failed to load transform for sha1: %ld\n",
		       PTR_ERR(tfm));
		return;
	}

	desc.tfm = tfm;
	desc.flags = 0;

	sg_init_one(&sg, data, nbytes);
	crypto_hash_digest(&desc, &sg, nbytes, result);
	crypto_free_hash(tfm);
}

static void range_stat(u64 index, atomic_t *dist)
{
	if (index < R1) {
		atomic_inc(&dist[0]);
	} else if (index < R2) {
		atomic_inc(&dist[1]);
	} else if (index < R3) {
		atomic_inc(&dist[2]);
	} else {
		atomic_inc(&dist[3]);
	}
}

static void hashb_rw(struct hashb* hashb, struct bio *bio)
{
	u8 ihash[20];
	u8 chash[20];

	u64 index = bio->bi_sector >> SECTORS_PER_PAGE_SHIFT;
	void *data = page_address(bio_page(bio));

	switch (bio_data_dir(bio)) {
	case READ:
		atomic_inc(&hashb->stats.num_reads);
		break;
	case WRITE:
		atomic_inc(&hashb->stats.num_writes);
#if 1
		sha1_hash(&index, sizeof(u64), ihash);
		sha1_hash(data, PAGE_SIZE, chash);
#else
		trcd_hash(&index, sizeof(u64), ihash);
		trcd_hash(data, PAGE_SIZE, chash);
#endif

		range_stat(SMT_INDEX(*(u64*)ihash), hashb->stats.ihash_dist);
		range_stat(SMT_INDEX(*(u64*)chash), hashb->stats.chash_dist);
		break;
	}
}
/*
 * Handler function for all hashb I/O requests.
 */
static void hashb_make_request(struct request_queue *queue, struct bio *bio)
{
	struct hashb *hashb = queue->queuedata;

	down_read(&hashb->init_lock);

	hashb_rw(hashb, bio);
	bio_endio(bio, 0);

	up_read(&hashb->init_lock);

	return;
}
static void destroy_device(struct hashb *hashb)
{

	if (hashb->disk) {
		del_gendisk(hashb->disk);
		put_disk(hashb->disk);
	}

	if (hashb->queue)
		blk_cleanup_queue(hashb->queue);
}

static int create_device(struct hashb *hashb, int device_id)
{
	int ret = -ENOMEM;

	init_rwsem(&hashb->init_lock);
	hashb->init_done = 0;

	hashb->queue = blk_alloc_queue(GFP_KERNEL);

	if (!hashb->queue) {
		pr_err("Error allocating disk queue for device %d\n",
			device_id);
		goto out;
	}

	blk_queue_make_request(hashb->queue, hashb_make_request);
	hashb->queue->queuedata = hashb;

	 /* gendisk structure */
	hashb->disk = alloc_disk(1);
	if (!hashb->disk) {
		pr_warning("Error allocating disk structure for device %d\n",
			device_id);
		goto out_free_queue;
	}

	hashb->disk->major = hashb_major;
	hashb->disk->first_minor = device_id;
	hashb->disk->fops = &hashb_devops;
	hashb->disk->queue = hashb->queue;
	hashb->disk->private_data = hashb;
	hashb_stats_init(&hashb->stats);
	snprintf(hashb->disk->disk_name, 16, "hashb%d", device_id);

	set_capacity(hashb->disk, DEFAULT_DISKSIZE * MULTIPLE);

	/*
	 * To ensure that we always get PAGE_SIZE aligned
	 * and n*PAGE_SIZED sized I/O requests.
	 */
	blk_queue_physical_block_size(hashb->disk->queue, PAGE_SIZE);
	blk_queue_logical_block_size(hashb->disk->queue,
					PAGE_SIZE);
	blk_queue_io_min(hashb->disk->queue, PAGE_SIZE);
	blk_queue_io_opt(hashb->disk->queue, PAGE_SIZE);
	blk_queue_max_hw_sectors(hashb->disk->queue, MULTIPLE);

	add_disk(hashb->disk);

	ret = sysfs_create_group(&disk_to_dev(hashb->disk)->kobj,
				&hashb_disk_attr_group);
	if (ret < 0) {
		pr_warning("Error creating sysfs group");
		goto out_free_disk;
	}

	hashb->init_done = 1;

	return 0;

out_free_disk:
	del_gendisk(hashb->disk);
	put_disk(hashb->disk);
out_free_queue:
	blk_cleanup_queue(hashb->queue);
out:
	return ret;
}

int init_module(void)
{
	int ret, dev_id;

	if (hashb_num_devices > max_num_devices) {
		pr_warning("Invalid value for num_devices: %u\n",
				hashb_num_devices);
		ret = -EINVAL;
		goto out;
	}

	hashb_major = register_blkdev(0, "hashb");
	if (hashb_major <= 0) {
		pr_warning("Unable to get major number\n");
		ret = -EBUSY;
		goto out;
	}

	if (!hashb_num_devices) {
		pr_info("num_devices not specified. Using default: 1\n");
		hashb_num_devices = 1;
	}

	/* Allocate the device array and initialize each one */
	pr_info("Creating %u devices ...\n", hashb_num_devices);
	hashb_devices = kzalloc(hashb_num_devices * sizeof(struct hashb), GFP_KERNEL);
	if (!hashb_devices) {
		ret = -ENOMEM;
		goto unregister;
	}

	for (dev_id = 0; dev_id < hashb_num_devices; dev_id++) {
		ret = create_device(&hashb_devices[dev_id], dev_id);
		if (ret)
			goto free_devices;
	}

	pr_emerg("successfully load hashb module\n");
	return 0;

free_devices:
	while (dev_id)
		destroy_device(&hashb_devices[--dev_id]);
	kfree(hashb_devices);
unregister:
	unregister_blkdev(hashb_major, "hashb");
out:
	return ret;
}

void cleanup_module(void) {
	int i;
	struct hashb *hashb;

	for (i = 0; i < hashb_num_devices; i++) {
		hashb = &hashb_devices[i];

		get_disk(hashb->disk);
		destroy_device(hashb);
		put_disk(hashb->disk);
	}

	unregister_blkdev(hashb_major, "hashb");
	kfree(hashb_devices);
	pr_emerg("successfully unload hashb module\n");
}

module_param(hashb_num_devices, uint, 0);
MODULE_PARM_DESC(hashb_num_devices, "Number of hashb devices");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Timothy Yo <yyou4@binghamton.edu>");
MODULE_DESCRIPTION("Sector hash Block Device");
