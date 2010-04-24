/*
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * expl wrote this file. As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.
 * ----------------------------------------------------------------------------
 */

#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

extern const char * const sys_errlist[];

#define TRUE 0
#define FALSE 1

/*parsing states*/
enum {
	S_NAME,
	S_DUMMY,
	S_VAL,
	S_END
};

/*value types*/
enum {
	T_INT,
	T_STR,
	T_BOOL
};

struct key_rule {
	char *key;
	int val_type;
};

static struct key_rule key_rules[] = {
	{"rc_debug", T_BOOL},
	{"rc_info", T_BOOL},
	{"swapfile", T_STR},
	{"apm_enable", T_BOOL},
	{"apmd_enable", T_BOOL},
	{"apmd_flags", T_STR},
	{"devd_enable", T_BOOL},
	{"kldxref_enable", T_BOOL},
	{"kldxref_clobber", T_BOOL},
	{"kldxref_module_path", T_STR},
	{"pccard_enable", T_BOOL},
	{"pccard_mem", T_STR},
	{"pccard_ifconfig", T_STR},
	{"pccard_beep", T_INT},
	{"pccard_conf", T_STR},
	{"pccardd_flags", T_STR},
	{"pccard_ether_delay", T_STR},
	{"removable_interfaces", T_STR},
	{"local_startup", T_STR},
	{"script_name_sep", T_STR},
	{"hostname", T_STR},
	{"ipv6_enable", T_BOOL},
	{"nisdomainname", T_STR},
	{"dhclient_program", T_STR},
	{"dhclient_flags", T_STR},
	{"background_dhclient", T_BOOL},
	{"firewall_enable", T_BOOL},
	{"ipv6_firewall_enable", T_BOOL},
	{"firewall_script", T_STR},
	{"ipv6_firewall_script", T_STR},
	{"firewall_type", T_STR},
	{"firewall_quiet", T_BOOL},
	{"ipv6_firewall_quiet", T_BOOL},
	{"firewall_logging", T_BOOL},
	{"ipv6_firewall_logging", T_BOOL},
	{"firewall_flags", T_STR},
	{"ipv6_firewall_flags", T_STR},
	{"natd_program", T_STR},
	{"natd_enable", T_BOOL},
	{"natd_interface", T_STR},
	{"natd_flags", T_STR},
	{"ipfilter_enable", T_BOOL},
	{"ipfilter_program", T_STR},
	{"ipfilter_rules", T_STR},
	{"ipv6_ipfilter_rules", T_STR},
	{"ipfilter_flags", T_STR},
	{"ipnat_enable", T_BOOL},
	{"ipnat_program", T_STR},
	{"ipnat_rules", T_STR},
	{"ipnat_flags", T_STR},
	{"ipmon_enable", T_BOOL},
	{"ipmon_program", T_STR},
	{"ipmon_flags", T_STR},
	{"ipfs_enable", T_BOOL},
	{"ipfs_program", T_STR},
	{"ipfs_flags", T_STR},
	{"tcp_extensions", T_BOOL},
	{"log_in_vain", T_INT},
	{"tcp_keepalive", T_BOOL},
	{"tcp_drop_synfin", T_BOOL},
	{"icmp_drop_redirect", T_BOOL},
	{"icmp_log_redirect", T_BOOL},
	{"icmp_bmcastecho", T_BOOL},
	{"ip_portrange_first", T_INT},
	{"ip_portrange_last", T_INT},
	{"ifconfig_*", T_STR},
	{"wlans_*", T_STR},
	{"ipv6_ifconfig_*", T_STR},
	{"ipv6_default_interface", T_STR},
	{"cloned_interfaces", T_STR},
	{"gifconfig_*", T_STR},
	{"spppconfig_*", T_STR},
	{"zfs_enable", T_BOOL},
	{"ppp_enable", T_BOOL},
	{"ppp_mode", T_STR},
	{"ppp_nat", T_BOOL},
	{"ppp_user", T_STR},
	{"rc_conf_files", T_STR},
	{"gbde_autoattach_all", T_BOOL},
	{"gbde_devices", T_STR},
	{"fsck_y_enable", T_BOOL},
	{"background_fsck", T_BOOL},
	{"background_fsck_delay", T_INT},
	{"netfs_types", T_STR},
	{"extra_netfs_types", T_STR},
	{"syslogd_enable", T_BOOL},
	{"syslogd_program", T_STR},
	{"syslogd_flags", T_STR},
	{"inetd_enable", T_BOOL},
	{"inetd_program", T_STR},
	{"inetd_flags", T_STR},
	{"named_enable", T_BOOL},
	{"named_rcng", T_BOOL},
	{"named_program", T_STR},
	{"named_flags", T_STR},
	{"named_pidfile", T_STR},
	{"named_chrootdir", T_STR},
	{"named_chroot_autoupdate", T_BOOL},
	{"named_symlink_enable", T_BOOL},
	{"kerberos5_server_enable", T_BOOL},
	{"kerberos5_server", T_STR},
	{"kadmind5_server_enable", T_BOOL},
	{"kpasswdd_server", T_STR},
	{"rwhod_enable", T_BOOL},
	{"rwhod_flags", T_STR},
	{"amd_enable", T_BOOL},
	{"amd_flags", T_STR},
	{"amd_map_program", T_STR},
	{"update_motd", T_BOOL},
	{"nfs_client_enable", T_BOOL},
	{"nfs_access_cache", T_INT},
	{"nfs_server_enable", T_BOOL},
	{"nfs_server_flags", T_STR},
	{"mountd_enable", T_BOOL},
	{"weak_mountd_authentication", T_BOOL},
	{"nfs_reserved_port_only", T_BOOL},
	{"nfs_bufpackets", T_INT},
	{"rpc_lockd_enable", T_BOOL},
	{"rpc_statd_enable", T_BOOL},
	{"rpcbind_program", T_STR},
	{"rpcbind_enable", T_BOOL},
	{"rpcbind_flags", T_STR},
	{"keyserv_enable", T_BOOL},
	{"keyserv_flags", T_STR},
	{"pppoed_enable", T_BOOL},
	{"pppoed_provider", T_STR},
	{"pppoed_flags", T_STR},
	{"pppoed_interface", T_STR},
	{"timed_enable", T_BOOL},
	{"timed_flags", T_STR},
	{"ntpdate_enable", T_BOOL},
	{"ntpdate_program", T_STR},
	{"ntpdate_flags", T_STR},
	{"ntpd_enable", T_BOOL},
	{"ntpd_program", T_STR},
	{"ntpd_flags", T_STR},
	{"nis_client_enable", T_BOOL},
	{"nis_client_flags", T_STR},
	{"nis_ypset_enable", T_BOOL},
	{"nis_ypset_flags", T_STR},
	{"nis_server_enable", T_BOOL},
	{"nis_server_flags", T_STR},
	{"nis_ypxfrd_enable", T_BOOL},
	{"nis_ypxfrd_flags", T_STR},
	{"nis_yppasswdd_enable", T_BOOL},
	{"nis_yppasswdd_flags", T_STR},
	{"rpc_ypupdated_enable", T_BOOL},
	{"defaultrouter", T_STR},
	{"ipv6_defaultrouter", T_STR},
	{"static_routes", T_STR},
	{"ipv6_static_routes", T_STR},
	{"natm_static_routes", T_STR},
	{"gateway_enable", T_BOOL},
	{"ipv6_gateway_enable", T_BOOL},
	{"router_enable", T_BOOL},
	{"ipv6_router_enable", T_BOOL},
	{"router", T_STR},
	{"ipv6_router", T_STR},
	{"router_flags", T_STR},
	{"ipv6_router_flags", T_STR},
	{"mrouted_enable", T_BOOL},
	{"mroute6d_enable", T_BOOL},
	{"mrouted_flags", T_STR},
	{"mroute6d_flags", T_STR},
	{"mroute6d_program", T_STR},
	{"rtadvd_enable", T_BOOL},
	{"rtadvd_interfaces", T_STR},
	{"ipxgateway_enable", T_BOOL},
	{"ipxrouted_enable", T_BOOL},
	{"ipxrouted_flags", T_STR},
	{"arpproxy_all", T_BOOL},
	{"forward_sourceroute", T_BOOL},
	{"accept_sourceroute", T_BOOL},
	{"rarpd_enable", T_BOOL},
	{"rarpd_flags", T_STR},
	{"bootparamd_enable", T_BOOL},
	{"bootparamd_flags", T_STR},
	{"stf_interface_ipv4addr", T_STR},
	{"stf_interface_ipv4plen", T_INT},
	{"stf_interface_ipv6_ifid", T_STR},
	{"stf_interface_ipv6_slaid", T_STR},
	{"ipv6_faith_prefix", T_STR},
	{"ipv6_ipv4mapping", T_BOOL},
	{"atm_enable", T_BOOL},
	{"atm_load", T_STR},
	{"atm_netif_*", T_STR},
	{"atm_sigmgr_*", T_STR},
	{"atm_prefix_*", T_STR},
	{"atm_macaddr_*", T_STR},
	{"atm_arpserver_*", T_STR},
	{"atm_scsparp_*", T_BOOL},
	{"atm_pvcs", T_STR},
	{"atm_arps", T_STR},
	{"natm_interfaces", T_STR},
	{"keybell", T_STR},
	{"keymap", T_STR},
	{"keyrate", T_STR},
	{"keychange", T_STR},
	{"cursor", T_STR},
	{"scrnmap", T_STR},
	{"font8x16", T_STR},
	{"font8x14", T_STR},
	{"font8x8", T_STR},
	{"blanktime", T_INT},
	{"saver", T_STR},
	{"moused_enable", T_STR},
	{"moused_type", T_STR},
	{"moused_port", T_STR},
	{"moused_flags", T_STR},
	{"mousechar_start", T_INT},
	{"allscreens_flags", T_STR},
	{"allscreens_kbdflags", T_STR},
	{"cron_enable", T_BOOL},
	{"cron_program", T_STR},
	{"cron_flags", T_STR},
	{"lpd_program", T_STR},
	{"lpd_enable", T_BOOL},
	{"lpd_flags", T_STR},
	{"mta_start_script", T_STR},
	{"dumpdev", T_STR},
	{"dumpdir", T_STR},
	{"savecore_flags", T_STR},
	{"enable_quotas", T_BOOL},
	{"check_quotas", T_BOOL},
	{"accounting_enable", T_BOOL},
	{"ibcs2_enable", T_BOOL},
	{"ibcs2_loaders", T_STR},
	{"linux_enable", T_BOOL},
	{"osf1_enable", T_BOOL},
	{"svr4_enable", T_BOOL},
	{"sysvipc_enable", T_BOOL},
	{"clear_tmp_enable", T_BOOL},
	{"ldconfig_paths", T_STR},
	{"ldconfig_paths_aout", T_STR},
	{"ldconfig_insecure", T_BOOL},
	{"kern_securelevel_enable", T_BOOL},
	{"kern_securelevel", T_INT},
	{"lomac_enable", T_BOOL},
	{"start_vinum", T_BOOL},
	{"sshd_program", T_STR},
	{"sshd_enable", T_BOOL},
	{"sshd_flags", T_STR},
	{"usbd_enable", T_BOOL},
	{"usbd_flags", T_STR},
	{"hald_enable", T_BOOL},
	{"dbus_enable", T_BOOL},
	{NULL, 0}
};

ssize_t chlen(const char *str){
	ssize_t size;
	char ch;
	
	if(str == NULL)
		return 0;
		
	for(size = 0;;size++){
		ch = str[size];
		
		if(ch == (char)0)
			break;
	}
	
	return size;
}

/*fast implementation of itoa*/
void _itoa(int value, char* result, int base) {
	if(base < 2 || base > 36){
		*result = '\0';
		return;
	}
	
	char* ptr = result, *ptr1 = result, tmp_char;
	int tmp_value;
	
	do{
		tmp_value = value;
		value /= base;
		*ptr++ = "zyxwvutsrqponmlkjihgfedcba9876543210123456789abcdefghi\
		jklmnopqrstuvwxyz" [35 + (tmp_value - value * base)];
	} while(value);
	
	if(tmp_value < 0)
		*ptr++ = '-';
	*ptr-- = '\0';
	while(ptr1 < ptr){
		tmp_char = *ptr;
		*ptr--= *ptr1;
		*ptr1++ = tmp_char;
	}
}

/*malloc wrapper for itoa*/
char *itoa(int n){
	char s[17], *str;
	ssize_t size;
	
	memset(s, 0, 17);
	
	_itoa(n, s, 10);	
	size = chlen(s);
	
	str = (char *)malloc(size + 1);
	assert(str != NULL);
	memcpy(str, s, size);
	str[size] = (char)0;
	
	return str;
}

/*printf is bloated :(*/
ssize_t print(int d, const char *str){
	return write(d, str, chlen(str));
}

void print_usage(char **argv){
	print(0, argv[0]);
	print(0, " [config file]\n");
}

void print_error(const char *str){
	print(2, "Error: ");
	print(2, str);
	print(2, "\n");
}

char *readline(int fd){
	char *l, ch;
	ssize_t s, ss;
	
	l = (void *)malloc(sizeof(char));
	assert(l != NULL);
	
	l[0] = (char)0;
	
	for(ss = 1;;ss++){
		if((s = read(fd, &ch, sizeof(char))) == -1){
			print_error(sys_errlist[errno]);
			
			free(l);
			close(fd);
			
			exit(FALSE);
		}
		else if(!s){
			free(l);
			return NULL;
		}
		if(ch == '\n')
			break;
		
		l = (void *)realloc(l, ss);
		l[ss - 1] = ch;
		l[ss] = (char)0;
	}
	
	return l;
}

void print_syntax_error(int line, int ch, const char *str){
	char *s;
	
	print(0, "Line #");
	print(0, s = itoa(line));
	free(s);
	print(0, " character #");
	print(0, s = itoa(ch));
	free(s);
	print(0, " : ");
	print(0, str);
}

char *find_ch(char ch, char *str){
	int i;
	
	for(i = 0; str[i] != (char)0; i++){
		if(str[i] == ch)
			return &str[i];
	}
	
	return NULL;
}

int check_key(char *l, ssize_t s, int line, int *value_t){
	int rv = TRUE, i, ii, state = FALSE;
	char key[s];
	
	/*finding key's borders*/
	for(i = 0; i != s && (l[i] == (char)32 || l[i] == (char)9); i++);
	ii = (find_ch('=', l) - l);
	for(;ii != 0 && (l[ii] == (char)32 || l[ii] == (char)9); ii--);

	int pos = ii - i;
	
	memcpy(key, &l[i], pos);
	key[pos] = (char)0;
	
	for(ii = 0; ii != pos; ii++){
		if(((key[ii] < 48) ||
		    (key[ii] > 57 && key[ii] < 65) ||
		    (key[ii] > 90 && key[ii] < 97) ||
		    (key[ii] > 122)) &&
		   (key[ii] != '_')){
			
			print_syntax_error(line, i + ii + 1, 
			"Illegal character used in key's name!\n");
			rv = FALSE;
		}
	}
	
	pos = ii;
		
	for(ii = 0; key_rules[ii].key != NULL; ii++){
		for(pos = 0; key_rules[ii].key[pos]; pos++)
			if(key_rules[ii].key[pos] == '*')			
				break;

		if(s >= pos && !strncmp(key_rules[ii].key, key, pos)){
			state = TRUE;
			*value_t = key_rules[ii].val_type;
			
			break;
		}
	}
		
	if(state == FALSE){
		print_syntax_error(line + 1, i + 1, 
		"Unknown key! Please double check if it is a correct 3rd party configuration key.\n");
		rv = FALSE;
	}
	
	return rv;
}

int check_value(char *l, ssize_t s, int line, int value_t){
	int i, ii, state = FALSE;
	char value[s];
	
	/*finding value's borders*/
	ii = (find_ch('=', l) - l) + 1;
	for(; ii != s && (l[ii] == (char)32 || l[ii] == (char)9); ii++);
	for(i = s - 1; i != 0 && (l[i] == (char)32 || l[i] == (char)9); i--);
	
	if(l[ii] == (char)0 || ii == i){
		print_syntax_error(line, ii, "Value is missing!\n");
		
		return state;
	}
	
	if(l[ii] != '"' || l[i] != '"'){
		print_syntax_error(line, ii, "Value needs to be in quotations!\n");
		
		return state;
	}
	
	ii++;
	
	if(ii == i){
		print_syntax_error(line, ii, "Warning! A dummy value.\n");
		
		return state;
	}
	
	int pos = i - ii;
	
	memcpy(value, &l[ii], pos);
	value[pos] = (char)0;
	
	switch(value_t){
		case T_INT:
			for(i = 0; i != pos; i++){
				if((value[i] < 48 || value[i] > 57) && value[i] != '-'){
					print_syntax_error(line, ii, 
					"Warning! Expected integer value.\n");
					
					return state;
				}
				else
					state = TRUE;
			}
		break;
		case T_BOOL:
			if((pos == 3 && !strcmp(value, "YES")) || 
			   (pos == 2 && !strcmp(value, "NO" )) ){
				state = TRUE;
			}
			else {
				print_syntax_error(line, ii, 
				"Warning! Expected bool value.\n");
				
				return FALSE;
			}
		break;
		case T_STR:
			state = TRUE;
		break;
	}
	
	return state;
}

int do_check(int fd){
	char *l;
	ssize_t s, ss;
	int rv = TRUE, i, ii, state, o_state, value_t;
	
	for(i = 0; (l = readline(fd)) != NULL; i++){
		state = S_NAME;
		
		s = chlen(l);
		
		state = S_NAME;
		
		for(ss = 0; ss != s; ss++){
			if(((l[ss] < 32) || (l[ss] > 126))
			&& (l[ss] != '\n') && (l[ss] != '\t')){
				print_syntax_error(i + 1, ss + 1,
				"is not a valid ASCII character!\n");
				rv = FALSE;
				state = S_END;
			}
			
			if(l[ss] == '#'){
				l[ss] = (char)0;
				s = ss;
				
				break;
			}
			
			if((ss + 1) == s){
				o_state = state;
				state = S_DUMMY;
				for(ii = 0; ii != s; ii++)
					if(l[ii] != (char)32){
						state = o_state;
					
						break;
					}
				if(s == 0)
					state = o_state;
				if(state == S_NAME){
					print_syntax_error(i + 1, ss + 1,
					"statement is not complete!\n");
					rv = FALSE;
					state = S_END;
				}
				
				break;
			}
			if(l[ss] == '=')
				state = S_VAL;
		}
		if(state == S_NAME && l[0] != (char)0){
			print_syntax_error(i + 1, ss + 1,
			"statement is not complete!\n");
			rv = FALSE;
		}		
		else if(state == S_VAL){
			rv = check_key(l, s, i, &value_t);
			
			if(rv == TRUE)
				rv = check_value(l, s, i, value_t);
		}

		free(l);
	}
	
	return rv;
}

int main(int argc, char **argv){
	int fd, stat;
	
	if(argc != 2)
		print_usage(argv);
	
	if((fd = open(argv[1], O_RDONLY)) == -1){
		print_error(sys_errlist[errno]);
		
		return FALSE;
	}

	stat = do_check(fd);
	close(fd);
	
	return stat;
}
