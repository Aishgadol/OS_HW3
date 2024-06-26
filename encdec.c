#include <linux/ctype.h>
#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/proc_fs.h>
#include <linux/fcntl.h>
#include <asm/system.h>
#include <asm/uaccess.h>
#include <linux/string.h>

#include "encdec.h"

#define MODULE_NAME "encdec"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Idan Morad, Or Dinar");

int 	encdec_open(struct inode *inode, struct file *filp);
int 	encdec_release(struct inode *inode, struct file *filp);
int 	encdec_ioctl(struct inode *inode, struct file *filp, unsigned int cmd, unsigned long arg);

ssize_t encdec_read_caesar( struct file *filp, char *buf, size_t count, loff_t *f_pos );
ssize_t encdec_write_caesar(struct file *filp, const char *buf, size_t count, loff_t *f_pos);

ssize_t encdec_read_xor( struct file *filp, char *buf, size_t count, loff_t *f_pos );
ssize_t encdec_write_xor(struct file *filp, const char *buf, size_t count, loff_t *f_pos);

int memory_size = 0;

MODULE_PARM(memory_size, "i");

int major = 0;
char* caesar_buffer;
char* xor_buffer;

struct file_operations fops_caesar = {
	.open 	 =	encdec_open,
	.release =	encdec_release,
	.read 	 =	encdec_read_caesar,
	.write 	 =	encdec_write_caesar,
	.llseek  =	NULL,
	.ioctl 	 =	encdec_ioctl,
	.owner 	 =	THIS_MODULE
};

struct file_operations fops_xor = {
	.open 	 =	encdec_open,
	.release =	encdec_release,
	.read 	 =	encdec_read_xor,
	.write 	 =	encdec_write_xor,
	.llseek  =	NULL,
	.ioctl 	 =	encdec_ioctl,
	.owner 	 =	THIS_MODULE
};
/*

*/
// Implemetation suggestion:
// -------------------------
// Use this structure as your file-object's private data structure
typedef struct {
	unsigned char key;
	int read_state;

} encdec_private_data;

int init_module(void)
{
	major = register_chrdev(major, MODULE_NAME, &fops_caesar);
	if(major < 0)
	{
		return major;
	}
	caesar_buffer = kmalloc(memory_size, GFP_KERNEL);
	memset(caesar_buffer, 0, memory_size);
	xor_buffer = kmalloc(memory_size, GFP_KERNEL);
	memset(xor_buffer, 0, memory_size);

	if (!caesar_buffer || !xor_buffer) {
		printk(KERN_ALERT "Failed to allocate memory\n");
		unregister_chrdev(major, MODULE_NAME);
		return -ENOMEM;
	}

	return 0;
}

	void cleanup_module(void)
{
	// Unregister device using its Major
	unregister_chrdev(major, MODULE_NAME);

	// Free buffer allocated memory
	if (caesar_buffer) {
		kfree(caesar_buffer);
		caesar_buffer = NULL;
	}
	if (xor_buffer) {
		kfree(xor_buffer);
		xor_buffer = NULL;
	}
}



int encdec_open(struct inode *inode, struct file *filp)
{
	int minor = MINOR(inode->i_rdev);

	if (minor == 0) {
		filp->f_op = &fops_caesar;
	} else if (minor == 1) {
		filp->f_op = &fops_xor;
	} else {
		return -ENODEV;
	}

	// Allocate memory for the file's private data
	encdec_private_data *private_data = kmalloc(sizeof(encdec_private_data), GFP_KERNEL);
	if (private_data == NULL) {
		return -ENOMEM;
	}

	private_data->key = 0;  // Initialize key to 0
	private_data->read_state = ENCDEC_READ_STATE_DECRYPT;  // Initialize read state to Decrypt

	filp->private_data = private_data;

	return 0;
}

int encdec_release(struct inode *inode, struct file *filp)
{
	// Free the allocated memory for 'filp->private_data' (using kfree)
		kfree(filp->private_data);
	return 0;
}

int encdec_ioctl(struct inode *inode, struct file *filp, unsigned int cmd, unsigned long arg)
{
     encdec_private_data *data = ( encdec_private_data *)filp->private_data;

    switch (cmd) {				//Switch case, according to the command the user inputs
        case ENCDEC_CMD_CHANGE_KEY:
            data->key = arg;
            break;
        case ENCDEC_CMD_SET_READ_STATE:
            if (arg == ENCDEC_READ_STATE_RAW || arg == ENCDEC_READ_STATE_DECRYPT)
                data->read_state = arg;
            else
                return -EINVAL;
            break;
        case ENCDEC_CMD_ZERO:
			if (MINOR(inode->i_rdev) == 0)
            memset(caesar_buffer, 0, memory_size);
			else
			memset(xor_buffer, 0, memory_size);
            break;
        default:
            return -ENOTTY;
    }

    return 0;
}


ssize_t encdec_read_caesar(struct file *filp, char *buf, size_t count, loff_t *f_pos)
{
    encdec_private_data *data = (encdec_private_data *)filp->private_data;
    int i;
    char *temp;
	int read_raw;

    // Check if we're trying to read beyond end of buffer
    if (*f_pos >= memory_size)
        return -EINVAL;

    size_t remaining_bytes = memory_size - *f_pos;

    // Check if count is greater than remaining bytes in the buffer
    if (count > remaining_bytes)
        count = remaining_bytes;

    // Determine if we need to read raw or decrypted data
    read_raw = (data->read_state == ENCDEC_READ_STATE_RAW);

    // Allocate temp buffer for decrypted data
    temp = kmalloc(count, GFP_KERNEL);
    if (!temp)
        return -ENOMEM;

    // Copy data from buffer to temp buffer
    memcpy(temp, caesar_buffer + *f_pos, count);

    // Decrypt the data if needed
    if (!read_raw) {
        int key = data->key;
        for (i = 0; i < count; i++) {
            temp[i] = ((temp[i] - key) + 128) % 128;
        }
    }

    // Copy the string, either RAW or decrypted. If it fails, we free allocated memory and return.
    if (copy_to_user(buf, temp, count)) {
        kfree(temp);
        return -EFAULT;
    }

    // Update the position and free the temporary buffer
    *f_pos += count;
    kfree(temp);
    return count;
}



ssize_t encdec_write_caesar(struct file *filp, const char *buf, size_t count, loff_t *f_pos)
{
     encdec_private_data *data = ( encdec_private_data *)filp->private_data;
    size_t remaining = memory_size - *f_pos;
    size_t written = 0;
    char *cipher_buf = caesar_buffer + *f_pos;				/***/
    int i;

    if (remaining == 0) {
        return -ENOSPC;
    }

    if (count > remaining) {
        count = remaining;
    }

    if (copy_from_user(cipher_buf, buf, count)) {
        return -EFAULT;
    }

	//Encryption
    for (i = 0; i < count; i++) {
        cipher_buf[i] = (cipher_buf[i] + data->key) % 128;
    }

    *f_pos += count;
    written = count;

    return written;
}

ssize_t encdec_read_xor( struct file *filp, char *buf, size_t count, loff_t *f_pos )
{
	encdec_private_data *data = (encdec_private_data*)filp->private_data;
    int i;
    char *temp;
	int read_raw;

    // Check if trying to read beyond end of buffer
    if (*f_pos >= memory_size)
        return -EINVAL;

    size_t remaining_bytes = memory_size - *f_pos;

    // Check if count is greater than remaining bytes
    if (count > remaining_bytes)
        count = remaining_bytes;

    // Determine if we need to read raw or decrypted data
     read_raw= (data->read_state == ENCDEC_READ_STATE_RAW);

    // Allocate temporary buffer for decrypted data
    temp = kmalloc(count, GFP_KERNEL);
    if (!temp)
        return -ENOMEM;

    // Copy data from buffer to temp buffer
    memcpy(temp, xor_buffer + *f_pos, count);

    // Decrypt the data if needed
    if (!read_raw) {
        for (i = 0; i < count; i++) {
        temp[i] = temp[i] ^ data->key;
    }
    }

    // Copy the string, either RAW or decrypted. If it fails, we free allocated memory and return.
    if (copy_to_user(buf, temp, count)) {
        kfree(temp);
        return -EFAULT;
    }

    // Update the position and free the temporary buffer
    *f_pos += count;
    kfree(temp);
    return count;
}


ssize_t encdec_write_xor(struct file *filp, const char *buf, size_t count, loff_t *f_pos)
{
    encdec_private_data *data = (encdec_private_data *)filp->private_data;
    size_t remaining = memory_size - *f_pos;
    size_t written = 0;
    char *cipher_buf = xor_buffer + *f_pos;				/***/
    int i;

    if (remaining == 0) {
        return -ENOSPC;
    }

    if (count > remaining) {
        count = remaining;
    }
	//Copy string from user to kernel.
    if (copy_from_user(cipher_buf, buf, count)) {
        return -EFAULT;
    }
	//encyrption
    for (i = 0; i < count; i++) {
        cipher_buf[i] = cipher_buf[i] ^ data->key;
    }

	//Update position and written words.
    *f_pos += count;
    written = count;
    return written;
}
