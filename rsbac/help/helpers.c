/************************************* */
/* Rule Set Based Access Control       */
/* Author and (c) 1999-2019:           */
/*   Amon Ott <ao@rsbac.org>           */
/* Helper functions for all parts      */
/* Last modified: 04/Jan/2019          */
/************************************* */

#include <rsbac/types.h>
#include <rsbac/error.h>
#include <rsbac/helpers.h>
#include <rsbac/rc_types.h>
#include <rsbac/getname.h>
#include <rsbac/cap_getname.h>
#include <rsbac/adf.h>

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <uapi/linux/magic.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/binfmts.h>
#include <net/sock.h>
#include <net/af_unix.h>
#include <rsbac/aci.h>
#include <rsbac/rkmem.h>
#include <rsbac/debug.h>
#ifdef CONFIG_RSBAC_RC
#include <rsbac/rc_getname.h>
#endif

int rsbac_get_vset_num(char * sourcename, rsbac_um_set_t * vset_p)
  {
    if (!sourcename || !vset_p)
      return -RSBAC_EINVALIDPOINTER;
    if (!strcmp(sourcename,"all")) {
      *vset_p = RSBAC_UM_VIRTUAL_ALL;
      return 0;
    }
    if (!strcmp(sourcename,"auto") || !strcmp(sourcename,"keep")) {
      *vset_p = RSBAC_UM_VIRTUAL_KEEP;
      return 0;
    }
    *vset_p = simple_strtoul(sourcename, NULL, 0);
    if(!*vset_p && strcmp(sourcename,"0"))
      return -RSBAC_EINVALIDVALUE;
    if (*vset_p > RSBAC_UM_VIRTUAL_MAX)
      return -RSBAC_EINVALIDVALUE;
    return 0;
  }

char * inttostr(char * str, int i)
  {
    int j = 0;
    
    if(!str)
      return(NULL);
      
    if (i<0)
      {
        str[j] = '-';
        j++;
        i = -i;
      }
    if (i>=10000)
      {
        str[j] = '0' + (i / 10000);
        j++;
      }
    if (i>=1000)
      {
        str[j] = '0' + ((i % 10000) / 1000);
        j++;
      }
    if (i>=100)
      {
        str[j] = '0' + ((i % 1000) / 100);
        j++;
      }
    if (i>=10)
      {
        str[j] = '0' + ((i % 100) / 10);
        j++;
      }
    str[j] = '0' + (i % 10);
    j++;
    str[j] = 0;
    return (str);
  };

char * ulongtostr(char * str, u_long i)
  {
    int    j = 0;
    u_long k = 1000000000;
    
    if(!str)
      return(NULL);

    if (i>=k)
      {
        str[j] = '0' + ((i / k) % 100);
        j++;
      }
    k /= 10;

    while (k>1)
      {
        if (i>=k)
          {
            str[j] = '0' + ((i % (k*10)) / k);
            j++;
          }
        k /= 10;
      };

    str[j] = '0' + (i % 10);
    j++;
    str[j] = 0;
    return (str);
  };

char * longtostr(char * str, long i)
  {
    int    j = 0;
    u_long k = 1000000000;
    
    if(!str)
      return(NULL);

    if (i<0)
      {
        str[0] = '-';
        j = 1;
        i = -i;
      }
    if (i>=k)
      {
        str[j] = '0' + ((i / k) % 100);
        j++;
      }
    k /= 10;

    while (k>1)
      {
        if (i>=k)
          {
            str[j] = '0' + ((i % (k*10)) / k);
            j++;
          }
        k /= 10;
      };

    str[j] = '0' + (i % 10);
    j++;
    str[j] = 0;
    return (str);
  };

char * u64tostrmac(char * str, __u64 i)
  {
    int    j = 0;
    __u64  k;

    if(!str)
      return(NULL);

    k = 1;
    for(j = RSBAC_MAC_MAX_CAT;j >= 0;j--)
      {
        if (i & k)
          str[j] = '1';
        else
          str[j] = '0';
        k<<=1;
      };

    str[RSBAC_MAC_NR_CATS] = 0;
    return (str);
  };

char * u64tostracl(char * str, __u64 i)
  {
    int    j = 0;
    __u64  k;

    if(!str)
      return(NULL);

    k = 1;
    for(j = ACLR_NONE - 1;j >= 0;j--)
      {
        if (i & k)
          str[j] = '1';
        else
          str[j] = '0';
        k<<=1;
      };

    str[ACLR_NONE] = 0;
    return (str);
  };

char * u32tostrcap(char * str, __u32 i)
  {
    int    j = 0;
    __u32  k;

    if(!str)
      return(NULL);

    k = 1;
    for(j = RSBAC_CAP_NONE - 1;j >= 0;j--)
      {
        if (i & k)
          str[j] = '1';
        else
          str[j] = '0';
        k<<=1;
      };

    str[RSBAC_CAP_NONE] = 0;
    return (str);
  };
int kcaptostrcap(char * str, rsbac_cap_vector_t i)
  {
    int    j = 0;
    int off;
    __u32  k;

    if(!str)
      return(-1);

    k = 1;
    for(j = RSBAC_CAP_NONE - 1;j >= 32;j--)
      {
        if (i.cap[1] & k)
          str[j-32] = '1';
        else
          str[j-32] = '0';
        k<<=1;
      };
    k = 1;
    off = RSBAC_CAP_NONE-32;
    for(j = 31+off;j >= off;j--)
      {
        if (i.cap[0] & k)
          str[j] = '1';
        else
          str[j] = '0';
        k<<=1;
      };

    str[RSBAC_CAP_NONE] = 0;

    return 0;
  };

int strcaptokcap(char * str, rsbac_cap_vector_t * i)
  {
    int    j;
    int    off;
    __u32  k = 1;
    
    if(!str)
      return -1;
    if (strlen(str) < RSBAC_CAP_NONE)
      return -1;

    for(j = RSBAC_CAP_NONE-1; j >= 32; j--)
      {
        if(str[j-32] != '0')
          {
            i->cap[1] |= k;
          }
        k <<= 1;
      }
    k = 1;
    off = RSBAC_CAP_NONE-32;
	for(j =31+off ;j >= off; j--) {
		if(str[j] != '0') {
			i->cap[0] |= k;
		}
		k <<= 1;
	}
/*    for(j=RSBAC_CAP_NONE;j<32;j++)
      {
        res |= k;
        k <<= 1;
      }*/
/*    *i_p = res;*/

    return 0;
  }
__u32 strtou32cap(char * str, __u32 * i_p)
  {
    int    j;
    __u32  k = 1, res=0;
    
    if(!str)
      return(0);

    if (strlen(str) < RSBAC_CAP_NONE)
      return(-1);
    for(j=RSBAC_CAP_NONE-1;j>=0;j--)
      {
        if(str[j] != '0')
          {
            res |= k;
          }
        k <<= 1;
      }
    for(j=RSBAC_CAP_NONE;j<32;j++)
      {
        res |= k;
        k <<= 1;
      }
    *i_p = res;
    return(res);
  };


#ifdef CONFIG_RSBAC_UM_VIRTUAL
rsbac_um_set_t rsbac_get_vset(void)
  {
    union rsbac_target_id_t        i_tid;
    union rsbac_attribute_value_t  i_attr_val;

    i_tid.process = task_pid(current);
    if(rsbac_get_attr(SW_GEN,
                        T_PROCESS,
                        i_tid,
                        A_vset,
                        &i_attr_val,
                        TRUE))
	return 0;
    else
    	return i_attr_val.vset;
  }
#endif

/* find the current owner of this process */
int rsbac_get_owner(rsbac_uid_t * user_p)
  {
#ifdef CONFIG_RSBAC_UM_VIRTUAL
    *user_p = RSBAC_GEN_UID(rsbac_get_vset(), __kuid_val(current_uid()));
#else
    *user_p = __kuid_val(current_uid());
#endif
    return 0;
  }

void rsbac_ds_get_error(const char * function, enum rsbac_attribute_t attr)
  {
    if(!function)
      return;
    if(attr != A_none)
      {
        char tmp[80];

        get_attribute_name(tmp, attr);
        rsbac_printk(KERN_WARNING
                     "%s: rsbac_get_attr() for %s returned error!\n",
                     function, tmp);
      }
    else
      {
        rsbac_printk(KERN_WARNING
                     "%s: rsbac_get_attr() returned error!\n",
                     function);
      }
  }

void rsbac_ds_get_error_num(const char * function, enum rsbac_attribute_t attr, int err)
  {
    char tmp2[80];

    if(!function)
      return;
    if(attr != A_none)
      {
        char tmp[80];

        get_attribute_name(tmp, attr);
        get_error_name(tmp2, err);
        rsbac_printk(KERN_WARNING
                     "%s: rsbac_get_attr() for %s returned error %s!\n",
                     function, tmp, tmp2);
      }
    else
      {
        get_error_name(tmp2, err);
        rsbac_printk(KERN_WARNING
                     "%s: rsbac_get_attr() returned error %s!\n",
                     function, tmp2);
      }
  }

void rsbac_ds_set_error(const char * function, enum rsbac_attribute_t attr)
  {
    if(!function)
      return;
    if(attr != A_none)
      {
        char tmp[80];

        get_attribute_name(tmp, attr);
        rsbac_printk(KERN_WARNING
                     "%s: rsbac_set_attr() for %s returned error!\n",
                     function, tmp);
      }
    else
      {
        rsbac_printk(KERN_WARNING
                     "%s: rsbac_set_attr() returned error!\n",
                     function);
      }
  }

void rsbac_ds_set_error_num(const char * function, enum rsbac_attribute_t attr, int err)
  {
    char tmp2[80];

    if(!function)
      return;
    if(attr != A_none)
      {
        char tmp[80];

        get_attribute_name(tmp, attr);
        get_error_name(tmp2, err);
        rsbac_printk(KERN_WARNING
                     "%s: rsbac_set_attr() for %s returned error %s!\n",
                     function, tmp, tmp2);
      }
    else
      {
        get_error_name(tmp2, err);
        rsbac_printk(KERN_WARNING
                     "%s: rsbac_set_attr() returned error %s!\n",
                     function, tmp2);
      }
  }

#ifdef CONFIG_RSBAC_RC
void rsbac_rc_ds_get_error(const char * function, enum rsbac_rc_item_t item)
  {
    if(!function)
      return;
    if(item != RI_none)
      {
        char tmp[80];

        get_rc_item_name(tmp, item);
        rsbac_printk(KERN_WARNING
                     "%s: rsbac_rc_get_item() for %s returned error!\n",
                     function, tmp);
      }
    else
      {
        rsbac_printk(KERN_WARNING
                     "%s: rsbac_rc_get_item() returned error!\n",
                     function);
      }
  }

void rsbac_rc_ds_set_error(const char * function, enum rsbac_rc_item_t item)
  {
    if(!function)
      return;
    if(item != RI_none)
      {
        char tmp[80];

        get_rc_item_name(tmp, item);
        rsbac_printk(KERN_WARNING
                     "%s: rsbac_rc_set_item() for %s returned error!\n",
                     function, tmp);
      }
    else
      {
        rsbac_printk(KERN_WARNING
                     "%s: rsbac_rc_set_item() returned error!\n",
                     function);
      }
  }
#endif

int rsbac_handle_filldir(const struct file *file, const char *name, const unsigned int namlen, const ino_t ino)
{
	enum   rsbac_target_t	       rsbac_target = T_NONE;
        union  rsbac_target_id_t       rsbac_target_id;
        union  rsbac_attribute_value_t rsbac_attribute_value;
	struct dentry *obj_dentry = NULL;
	int err = 1;

	if(!rsbac_initialized) {
		goto old_func;
	}

	if(!name || !file || !file->f_path.dentry || !file->f_path.dentry->d_sb
		 || !MAJOR(file->f_path.dentry->d_sb->s_dev))
		goto old_func;

        if (in_interrupt())
          {
            printk(KERN_WARNING "rsbac_handle_filldir(): called from interrupt: pid %u(%s)!\n",
                         current->pid, current->comm);
            goto old_func;
          }

	obj_dentry = lookup_one_len(name, file->f_path.dentry, namlen);
	if (!obj_dentry || IS_ERR(obj_dentry)) {
		goto old_func;
	}
	if (!obj_dentry->d_inode || IS_ERR(obj_dentry->d_inode)) {
		goto out_dput;
	}
	if (!obj_dentry->d_inode->i_mode || !obj_dentry->d_inode->i_sb || !obj_dentry->d_inode->i_sb->s_dev || !ino) {
		goto out_dput;
	}
	if (!obj_dentry->d_sb || !obj_dentry->d_sb->s_magic) {
		goto out_dput;
	}
	rsbac_pr_debug(aef, "[readdir(), sys_getdents()]: calling ADF\n");

	if (S_ISFIFO(obj_dentry->d_inode->i_mode)) {
		if(obj_dentry->d_sb->s_magic != PIPEFS_MAGIC) {
			rsbac_target = T_FIFO;
			rsbac_target_id.fifo.device = obj_dentry->d_inode->i_sb->s_dev;
			rsbac_target_id.fifo.inode  = ino;
			rsbac_target_id.fifo.dentry_p = obj_dentry;
		}
	} else
	if (S_ISDIR(obj_dentry->d_inode->i_mode)) {
		rsbac_target = T_DIR;
		rsbac_target_id.dir.device = obj_dentry->d_inode->i_sb->s_dev;
		rsbac_target_id.dir.inode = ino;
		rsbac_target_id.dir.dentry_p = obj_dentry;
	} else
	if (S_ISLNK(obj_dentry->d_inode->i_mode)) {
		rsbac_target = T_SYMLINK;
		rsbac_target_id.file.device = obj_dentry->d_inode->i_sb->s_dev;
		rsbac_target_id.file.inode = ino;
		rsbac_target_id.file.dentry_p = obj_dentry;
	} else
	if (S_ISSOCK(obj_dentry->d_inode->i_mode)) {
		if (obj_dentry->d_inode->i_sb->s_magic != SOCKFS_MAGIC) {
			rsbac_target = T_UNIXSOCK;
			rsbac_target_id.unixsock.device = obj_dentry->d_inode->i_sb->s_dev;
			rsbac_target_id.unixsock.inode = ino;
			rsbac_target_id.unixsock.dentry_p = obj_dentry;
		}
	} else {
		rsbac_target = T_FILE;
		rsbac_target_id.file.device = obj_dentry->d_inode->i_sb->s_dev;
		rsbac_target_id.file.inode = ino;
		rsbac_target_id.file.dentry_p = obj_dentry;
	}
	rsbac_attribute_value.dummy = 0;
	if (rsbac_target != T_NONE)
		if (!rsbac_adf_request(R_SEARCH,
					task_pid(current),
					rsbac_target,
					rsbac_target_id,
					A_none,
					rsbac_attribute_value))
		{
			err = 0;
			goto out_dput;
		}

out_dput:
	if (obj_dentry)
		dput(obj_dentry);
old_func:
	return err;
}
int rsbac_handle_rw_req(const struct file *file, struct rsbac_rw_req *rsbac_rw_req_obj)
{
	int err = 1;

	if(!rsbac_initialized) {
		goto out;
	}

/*	if (rsbac_rw_req_obj->rsbac_target != T_NONE){printk("i'm here! going out because of target ! =T_NONE\n");
                goto out;}
*/
	if(!file || !file->f_path.dentry || !file->f_path.dentry->d_sb
		 || !MAJOR(file->f_path.dentry->d_sb->s_dev)
		 || !file->f_path.dentry->d_sb->s_magic
		 || !file->f_path.dentry->d_inode
		 || IS_ERR(file->f_path.dentry->d_inode)
		 || !file->f_path.dentry->d_inode->i_mode
		 || !file->f_path.dentry->d_inode->i_ino)
		goto out;

        if (in_interrupt())
          {
            printk(KERN_WARNING "rsbac_handle_rw_req(): called from interrupt: pid %u(%s)!\n",
                         current->pid, current->comm);
            goto out;
          }

	rsbac_pr_debug(aef, "rsbac_handle_rw_req(): calling ADF\n");

	rsbac_rw_req_obj->rsbac_attribute = A_none;
        rsbac_rw_req_obj->rsbac_attribute_value.dummy = 0;

	if (S_ISFIFO(file->f_path.dentry->d_inode->i_mode)) {
		if(file->f_path.dentry->d_sb->s_magic != PIPEFS_MAGIC) {
			rsbac_rw_req_obj->rsbac_target = T_FIFO;
			rsbac_rw_req_obj->rsbac_target_id.fifo.device = file->f_path.dentry->d_inode->i_sb->s_dev;
			rsbac_rw_req_obj->rsbac_target_id.fifo.inode  = file->f_path.dentry->d_inode->i_ino;
			rsbac_rw_req_obj->rsbac_target_id.fifo.dentry_p = file->f_path.dentry;
		}
	} else
	if (file->f_path.dentry->d_inode->i_rsbac_memfd) {
		rsbac_rw_req_obj->rsbac_target = T_IPC;
		rsbac_rw_req_obj->rsbac_target_id.ipc.type = I_memfd;
		rsbac_rw_req_obj->rsbac_target_id.ipc.id.id_nr = file->f_path.dentry->d_inode->i_ino;
	} else
	if (S_ISREG(file->f_path.dentry->d_inode->i_mode)) {
		rsbac_rw_req_obj->rsbac_target = T_FILE;
		rsbac_rw_req_obj->rsbac_target_id.file.device = file->f_path.dentry->d_inode->i_sb->s_dev;
		rsbac_rw_req_obj->rsbac_target_id.file.inode  = file->f_path.dentry->d_inode->i_ino;
		rsbac_rw_req_obj->rsbac_target_id.file.dentry_p = file->f_path.dentry;
	} else
	if (S_ISSOCK(file->f_path.dentry->d_inode->i_mode)) {
		struct socket * sock = SOCKET_I(file->f_path.dentry->d_inode);
		if (sock->ops && (sock->ops->family == AF_UNIX)) {
			if (sock->sk) {
				if (unix_sk(unix_sk(sock->sk)->peer)) {
					if (unix_sk(unix_sk(sock->sk)->peer)->path.dentry && unix_sk(unix_sk(sock->sk)->peer)->path.dentry->d_inode) {
						rsbac_rw_req_obj->rsbac_target = T_UNIXSOCK;
						rsbac_rw_req_obj->rsbac_target_id.unixsock.device = unix_sk(unix_sk(sock->sk)->peer)->path.dentry->d_sb->s_dev;
						rsbac_rw_req_obj->rsbac_target_id.unixsock.inode  = unix_sk(unix_sk(sock->sk)->peer)->path.dentry->d_inode->i_ino;
						rsbac_rw_req_obj->rsbac_target_id.unixsock.dentry_p = unix_sk(unix_sk(sock->sk)->peer)->path.dentry;
					} else {
						rsbac_rw_req_obj->rsbac_target = T_IPC;
						rsbac_rw_req_obj->rsbac_target_id.ipc.type = I_anonunix;
						if (unix_sk(unix_sk(sock->sk)->peer)->path.dentry
								&& unix_sk(unix_sk(sock->sk)->peer)->path.dentry->d_inode
								&& SOCKET_I(unix_sk(unix_sk(sock->sk)->peer)->path.dentry->d_inode)->file
                                                        	&& SOCKET_I(unix_sk(unix_sk(sock->sk)->peer)->path.dentry->d_inode)->file->f_path.dentry
                                                        	&& SOCKET_I(unix_sk(unix_sk(sock->sk)->peer)->path.dentry->d_inode)->file->f_path.dentry->d_inode)
							rsbac_rw_req_obj->rsbac_target_id.ipc.id.id_nr = SOCKET_I(unix_sk(unix_sk(sock->sk)->peer)->path.dentry->d_inode)->file->f_path.dentry->d_inode->i_ino;
						else
							if (sock->file && sock->file->f_path.dentry && sock->file->f_path.dentry->d_inode)
								rsbac_rw_req_obj->rsbac_target_id.ipc.id.id_nr = sock->file->f_path.dentry->d_inode->i_ino;
						else
							rsbac_rw_req_obj->rsbac_target_id.ipc.id.id_nr = 0;
					}
				} else {
					if (unix_sk(sock->sk)->path.dentry && unix_sk(sock->sk)->path.dentry->d_inode) {
						rsbac_rw_req_obj->rsbac_target = T_UNIXSOCK;
						rsbac_rw_req_obj->rsbac_target_id.unixsock.device = unix_sk(sock->sk)->path.dentry->d_sb->s_dev;
						rsbac_rw_req_obj->rsbac_target_id.unixsock.inode  = unix_sk(sock->sk)->path.dentry->d_inode->i_ino;
						rsbac_rw_req_obj->rsbac_target_id.unixsock.dentry_p = unix_sk(sock->sk)->path.dentry;
					} else {
						rsbac_rw_req_obj->rsbac_target = T_IPC;
						rsbac_rw_req_obj->rsbac_target_id.ipc.type = I_anonunix;
						if (sock->file && sock->file->f_path.dentry && sock->file->f_path.dentry->d_inode)
							rsbac_rw_req_obj->rsbac_target_id.ipc.id.id_nr = sock->file->f_path.dentry->d_inode->i_ino;
						else
							rsbac_rw_req_obj->rsbac_target_id.ipc.id.id_nr = 0;
					}
				}
				if (sock->sk->sk_peer_pid) {
					rsbac_rw_req_obj->rsbac_attribute = A_process;
					rsbac_rw_req_obj->rsbac_attribute_value.process = sock->sk->sk_peer_pid;
				}
				else if (unix_sk(sock->sk)->peer && unix_sk(sock->sk)->peer->sk_peer_pid) {
					rsbac_rw_req_obj->rsbac_attribute = A_process;
					rsbac_rw_req_obj->rsbac_attribute_value.process = unix_sk(sock->sk)->peer->sk_peer_pid;
				} else {
					rsbac_rw_req_obj->rsbac_attribute = A_sock_type;
					rsbac_rw_req_obj->rsbac_attribute_value.sock_type = sock->type;
				}
			}
		}
	} else
	if (S_ISBLK(file->f_path.dentry->d_inode->i_mode)) {
		rsbac_rw_req_obj->rsbac_target = T_DEV;
		rsbac_rw_req_obj->rsbac_target_id.dev.type = D_block;
		rsbac_rw_req_obj->rsbac_target_id.dev.major = RSBAC_MAJOR(file->f_path.dentry->d_inode->i_rdev);
		rsbac_rw_req_obj->rsbac_target_id.dev.minor = RSBAC_MINOR(file->f_path.dentry->d_inode->i_rdev);
	} else
	if (S_ISCHR(file->f_path.dentry->d_inode->i_mode)) {
		rsbac_rw_req_obj->rsbac_target = T_DEV;
		rsbac_rw_req_obj->rsbac_target_id.dev.type = D_char;
                rsbac_rw_req_obj->rsbac_target_id.dev.major = RSBAC_MAJOR(file->f_path.dentry->d_inode->i_rdev);
                rsbac_rw_req_obj->rsbac_target_id.dev.minor = RSBAC_MINOR(file->f_path.dentry->d_inode->i_rdev);
	}
	if (rsbac_rw_req_obj->rsbac_target != T_NONE)
		if (!rsbac_adf_request(rsbac_rw_req_obj->rsbac_request,
					task_pid(current),
					rsbac_rw_req_obj->rsbac_target,
					rsbac_rw_req_obj->rsbac_target_id,
					A_none,
					rsbac_rw_req_obj->rsbac_attribute_value))
		{
			err = 0;
			goto out;
		}

out:
	return err;
}

int rsbac_handle_rw_up(struct rsbac_rw_req *rsbac_rw_req_obj)
{
	int err = 0;

	if (rsbac_rw_req_obj->rsbac_target != T_NONE) {
		rsbac_rw_req_obj->rsbac_new_target_id.dummy = 0;
		err = rsbac_adf_set_attr(rsbac_rw_req_obj->rsbac_request,
					task_pid(current),
					rsbac_rw_req_obj->rsbac_target,
					rsbac_rw_req_obj->rsbac_target_id,
					T_NONE,
					rsbac_rw_req_obj->rsbac_new_target_id,
					rsbac_rw_req_obj->rsbac_attribute,
					rsbac_rw_req_obj->rsbac_attribute_value);
		if (err)
			rsbac_printk(KERN_WARNING "rsbac_handle_rw_up(): rsbac_adf_set_attr() returned error\n");
	}

	return err;
}
