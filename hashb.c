#include <linux/export.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/genhd.h>

#define SECTOR_SHIFT 9
#define MULTIPLE (PAGE_SIZE >> SECTOR_SHIFT)
#define DEFAULT_DISKSIZE (32*1024*1024)

static int hashb_major = 0;
static int max_num_devices = 2;

/* Module params (documentation at end) */
static unsigned int hashb_num_devices = 0;

struct hashb{
	struct request_queue *queue;
	struct gendisk *disk;
	int init_done;
	/* Prevent concurrent execution of device init, reset and R/W request */
	struct rw_semaphore init_lock;
};

static struct hashb *hashb_devices = NULL;

static const struct block_device_operations hashb_devops = {
	.owner = THIS_MODULE
};

static void hashb_rw(struct bio *bio)
{
}
/*
 * Handler function for all hashb I/O requests.
 */
static void hashb_make_request(struct request_queue *queue, struct bio *bio)
{
	struct hashb *hashb = queue->queuedata;

	down_read(&hashb->init_lock);

	hashb_rw(bio);
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

	hashb->init_done = 1;
	add_disk(hashb->disk);

	return 0;

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

void cleanup_module(void)
{
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
