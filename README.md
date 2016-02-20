# Read_SEPolicy
Binary to convert SELinux Binary Policy into a readable format 


Example of output :

user_u:user_r:ssh_t
	xserver_t
			x_server { manage };
			tcp_socket { name_bind };
			x_screen { saver_setattr saver_hide saver_show };
			shm { getattr read associate unix_read };
			unix_stream_socket { connectto };
			lnk_file { read getattr };
