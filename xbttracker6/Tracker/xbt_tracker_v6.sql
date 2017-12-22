create table if not exists xbt_announce_log
(
	id int not null auto_increment,
	ipa int unsigned not null,
	port int not null,
	event int not null,
	info_hash blob not null,
	peer_id blob not null,
	downloaded bigint unsigned not null,
	left0 bigint unsigned not null,
	uploaded bigint unsigned not null,
	uid int not null,
	mtime int not null,
	primary key (id)
) engine = myisam;

create table if not exists xbt_config
(
	name varchar(255) not null,
	value varchar(255) not null
);

create table if not exists xbt_deny_from_hosts
(
	begin int not null,
	end int not null
);

create table if not exists xbt_files
(
	fid int not null auto_increment,
	info_hash blob not null,
	leechers int not null default 0,
	seeders int not null default 0,
	completed int not null default 0,
	flags int not null default 1,
	reg_time int not null,
	primary key (fid),
	unique key (info_hash(20))
);

create table if not exists xbt_files_users
(
	torrent_id int not null,
	peer_id blob not null,
	user_id int not null,
	ip int,
	ipv6 char(16), 
	port int,
	uploaded bigint unsigned not null default 0,
	downloaded bigint unsigned not null default 0,
	seeder int not null default 0,
	update_time int not null,
	expire_time int not null,
	xbt_error TINYTEXT not null,
	unique key (torrent_id, user_id),
	key (user_id)
);

create table if not exists xbt_scrape_log
(
	id int not null auto_increment,
	ipa int not null,
	info_hash blob,
	uid int not null,
	mtime int not null,
	primary key (id)
) engine = myisam;

create table if not exists xbt_users
(
	uid int not null auto_increment,
	-- name char(8) not null,
	-- pass blob not null,
	-- can_leech tinyint not null default 1,
	-- wait_time int not null default 0,
	-- peers_limit int not null default 0,
	-- torrents_limit int not null default 0,
	-- torrent_pass char(32) not null,
	-- torrent_pass_version int not null default 0,
	u_down_total bigint unsigned not null default 0,
	u_up_total bigint unsigned not null default 0,
	primary key (uid)
);