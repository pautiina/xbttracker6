#include "stdafx.h"
#include "server.h"

#include <boost/foreach.hpp>
#include <boost/format.hpp>
#include <sql/sql_query.h>
#include <iostream>
#include <sstream>
#include <signal.h>
#include <bt_misc.h>
#include <bt_strings.h>
#include <stream_int.h>
#include "transaction.h"

// TorrentPier begin
#ifdef WIN32
#include <Ws2tcpip.h>
#endif

/*
long long gcd(long long a, long long b) {
  long long c = 0;
  while (b) {
     c = a % b;
     a = b;
     b = c;        
  }
  return a;
}
*/
// TorrentPier end

static volatile bool g_sig_term = false;

Cserver::Cserver(Cdatabase& database, const std::string& table_prefix, bool use_sql, const std::string& conf_file):
	m_database(database)
{
	m_fid_end = 0;

	for (int i = 0; i < 8; i++)
		m_secret = m_secret << 8 ^ rand();
	m_conf_file = conf_file;
	m_table_prefix = table_prefix;
	m_time = ::time(NULL);
	m_use_sql = use_sql;
}

int Cserver::run()
{
	read_config();
	if (test_sql())
		return 1;
	if (m_epoll.create(1 << 10) == -1)
	{
		std::cerr << "epoll_create failed" << std::endl;
		return 1;
	}
	t_tcp_sockets lt;
	t_udp_sockets lu;

	// TorrentPier begin
	struct addrinfo hints, *res, *res0;
	char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	Csocket::start_up();

	BOOST_FOREACH(Cconfig::t_listen_ipas::const_reference j, m_config.m_listen_ipas)
	{
		BOOST_FOREACH(Cconfig::t_listen_ports::const_reference i, m_config.m_listen_ports)
		{
			//j:ip；i:端口
			//getaddrinfo，协议无关，v4/v6通用，提供独立于协议的名称解析
			if (getaddrinfo(j == "*" ? NULL : j.c_str(), i.c_str(), &hints, &res0)) {
				std::cerr << "getaddrinfo failed: " << Csocket::error2a(WSAGetLastError()) << std::endl;
				return 1;
			}
			for (res = res0; res; res = res->ai_next) {
				int s = ::socket(res->ai_family, res->ai_socktype, res->ai_protocol);
				if (s < 0)   //创建socket失败
				{
					std::cerr << "socket failed: " << Csocket::error2a(WSAGetLastError()) << std::endl;
					return 1;
				}
				Csocket l(s);
#ifdef IPV6_V6ONLY
				if (res->ai_family == AF_INET6 &&
					l.setsockopt(IPPROTO_IPV6, IPV6_V6ONLY, true)) {
					std::cerr << "IPV6_V6ONLY failed: " << Csocket::error2a(WSAGetLastError()) << std::endl;
				}
#endif
				//socket是否阻塞
				if (l.blocking(false))
					std::cerr << "blocking failed: " << Csocket::error2a(WSAGetLastError()) << std::endl;
				//绑定本机端口
				else if (l.setsockopt(SOL_SOCKET, SO_REUSEADDR, true),
					::bind(s, res->ai_addr, res->ai_addrlen))
					std::cerr << "bind failed: " << Csocket::error2a(WSAGetLastError()) << std::endl;
				//监听端口
				else if (l.listen())
					std::cerr << "listen failed: " << Csocket::error2a(WSAGetLastError()) << std::endl;
				else
				{
					//getnameinfo，协议无关，v4/v6通用，获得全部主机名
					if (getnameinfo(res->ai_addr, res->ai_addrlen, hbuf, sizeof(hbuf), sbuf, sizeof(sbuf), NI_NUMERICHOST | NI_NUMERICSERV))
						std::cerr << "getnameinfo failed: " << Csocket::error2a(WSAGetLastError()) << std::endl;
					else
						//成功开始监听
						std::cerr << "Listen to " << hbuf << " " << sbuf << std::endl;
#ifdef SO_ACCEPTFILTER
					accept_filter_arg afa;
					bzero(&afa, sizeof(afa));
					strcpy(afa.af_name, "httpready");
					if (l.setsockopt(SOL_SOCKET, SO_ACCEPTFILTER, &afa, sizeof(afa)))
						std::cerr << "setsockopt failed: " << Csocket::error2a(WSAGetLastError()) << std::endl;
#elif TCP_DEFER_ACCEPT
					if (l.setsockopt(IPPROTO_TCP, TCP_DEFER_ACCEPT, true))
						std::cerr << "setsockopt failed: " << Csocket::error2a(WSAGetLastError()) << std::endl;
#endif
					lt.push_back(Ctcp_listen_socket(this, l));
					if (!m_epoll.ctl(EPOLL_CTL_ADD, l, EPOLLIN | EPOLLOUT | EPOLLPRI | EPOLLERR | EPOLLHUP | EPOLLET, &lt.back()))
						continue;
				}
				return 1;
			}
		}

		/*
		BOOST_FOREACH(Cconfig::t_listen_ports::const_reference i, m_config.m_listen_ports)
		{
			Csocket l;
			if (l.open(SOCK_DGRAM) == INVALID_SOCKET)
				std::cerr << "socket failed: " << Csocket::error2a(WSAGetLastError()) << std::endl;
			else if (l.setsockopt(SOL_SOCKET, SO_REUSEADDR, true),
				l.bind(j, htons(i)))
				std::cerr << "bind failed: " << Csocket::error2a(WSAGetLastError()) << std::endl;
			else
			{
				lu.push_back(Cudp_listen_socket(this, l));
				if (!m_epoll.ctl(EPOLL_CTL_ADD, l, EPOLLIN | EPOLLOUT | EPOLLPRI | EPOLLERR | EPOLLHUP | EPOLLET, &lu.back()))
					continue;
			}
			return 1;
		}
		*/
	}
	// TorrentPier end

	clean_up();
	read_db_deny_from_hosts();
	read_db_files();
	read_db_users();
	write_db_files();
	write_db_users();
#ifndef WIN32
	if (m_config.m_daemon)
	{
#if 1
		if (daemon(true, false))
			std::cerr << "daemon failed" << std::endl;
#else
		switch (fork())
		{
		case -1:
			std::cerr << "fork failed" << std::endl;
			break;
		case 0:
			break;
		default:
			exit(0);
		}
		if (setsid() == -1)
			std::cerr << "setsid failed" << std::endl;
#endif
		std::ofstream(m_config.m_pid_file.c_str()) << getpid() << std::endl;
		struct sigaction act;
		act.sa_handler = sig_handler;
		sigemptyset(&act.sa_mask);
		act.sa_flags = 0;
		if (sigaction(SIGTERM, &act, NULL))
			std::cerr << "sigaction failed" << std::endl;
		act.sa_handler = SIG_IGN;
		if (sigaction(SIGPIPE, &act, NULL))
			std::cerr << "sigaction failed" << std::endl;
	}
#endif
#ifdef EPOLL
	const int c_events = 64;

	epoll_event events[c_events];
#else
	fd_set fd_read_set;
	fd_set fd_write_set;
	fd_set fd_except_set;
#endif
	while (!g_sig_term)
	{
#ifdef EPOLL
		int r = m_epoll.wait(events, c_events, 5000);
		if (r == -1)
			std::cerr << "epoll_wait failed: " << errno << std::endl;
		else
		{
			int prev_time = m_time;
			m_time = ::time(NULL);
			for (int i = 0; i < r; i++)
				reinterpret_cast<Cclient*>(events[i].data.ptr)->process_events(events[i].events);
			if (m_time == prev_time)
				continue;
			for (t_connections::iterator i = m_connections.begin(); i != m_connections.end(); )
			{
				if (i->run())
					i = m_connections.erase(i);
				else
					i++;
			}
		}
#else
		FD_ZERO(&fd_read_set);
		FD_ZERO(&fd_write_set);
		FD_ZERO(&fd_except_set);
		int n = 0;
		BOOST_FOREACH(t_connections::reference i, m_connections)
		{
			int z = i.pre_select(&fd_read_set, &fd_write_set);
			n = std::max(n, z);
		}
		BOOST_FOREACH(t_tcp_sockets::reference i, lt)
		{
			FD_SET(i.s(), &fd_read_set);
			n = std::max<int>(n, i.s());
		}
		BOOST_FOREACH(t_udp_sockets::reference i, lu)
		{
			FD_SET(i.s(), &fd_read_set);
			n = std::max<int>(n, i.s());
		}
		timeval tv;
		tv.tv_sec = 5;
		tv.tv_usec = 0;
		if (select(n + 1, &fd_read_set, &fd_write_set, &fd_except_set, &tv) == SOCKET_ERROR)
			std::cerr << "select failed: " << Csocket::error2a(WSAGetLastError()) << std::endl;
		else
		{
			m_time = ::time(NULL);
			BOOST_FOREACH(t_tcp_sockets::reference i, lt)
			{
				if (FD_ISSET(i.s(), &fd_read_set))
					accept(i.s());
			}
			BOOST_FOREACH(t_udp_sockets::reference i, lu)
			{
				if (FD_ISSET(i.s(), &fd_read_set))
					Ctransaction(*this, i.s()).recv();
			}
			for (t_connections::iterator i = m_connections.begin(); i != m_connections.end(); )
			{
				if (i->post_select(&fd_read_set, &fd_write_set))
					i = m_connections.erase(i);
				else
					i++;
			}
		}
#endif
		if (time() - m_read_config_time > m_config.m_read_config_interval)
		{
			read_config();
			BOOST_FOREACH(t_tcp_sockets::reference i, lt)
				i.process_events(EPOLLIN);
		}
		else if (time() - m_clean_up_time > m_config.m_clean_up_interval)
			clean_up();
		else if (time() - m_read_db_deny_from_hosts_time > m_config.m_read_db_interval)
			read_db_deny_from_hosts();

		// TorrentPier begin
		//else if (time() - m_read_db_files_time > m_config.m_read_db_interval)
		else if (time() - m_read_db_files_time > m_config.m_read_files_interval)
		// TorrentPier end

			read_db_files();
		else if (time() - m_read_db_users_time > m_config.m_read_db_interval)
			read_db_users();
		else if (m_config.m_write_db_interval && time() - m_write_db_files_time > m_config.m_write_db_interval)
			write_db_files();
		else if (m_config.m_write_db_interval && time() - m_write_db_users_time > m_config.m_write_db_interval)
			write_db_users();
	}
	write_db_files();
	write_db_users();
	unlink(m_config.m_pid_file.c_str());
	return 0;
}

void Cserver::accept(const Csocket& l)
{
	// TorrentPier begin
	sockaddr_storage a;
	while (1)
	{
		socklen_t cb_a = sizeof(sockaddr_storage);
		// TorrentPier end

		Csocket s = ::accept(l, reinterpret_cast<sockaddr*>(&a), &cb_a);
		if (s == SOCKET_ERROR)
		{
			if (WSAGetLastError() == WSAECONNABORTED)
				continue;
			if (WSAGetLastError() != WSAEWOULDBLOCK)
				std::cerr << "accept failed: " << Csocket::error2a(WSAGetLastError()) << std::endl;
			break;
		}

		// TorrentPier begin
		if (a.ss_family == AF_INET) {
			sockaddr_in *b = reinterpret_cast<sockaddr_in*>(&a);

			t_deny_from_hosts::const_iterator i = m_deny_from_hosts.lower_bound(ntohl(b->sin_addr.s_addr));
			if (i != m_deny_from_hosts.end() && ntohl(b->sin_addr.s_addr) >= i->second.begin)
			{
				m_stats.rejected_tcp++;
				continue;
			}
			m_stats.accepted_tcp4++;
		} else if (a.ss_family == AF_INET6) m_stats.accepted_tcp6++;
		// TorrentPier end

		m_stats.accepted_tcp++;
		if (s.blocking(false))
			std::cerr << "ioctlsocket failed: " << Csocket::error2a(WSAGetLastError()) << std::endl;
		std::auto_ptr<Cconnection> connection(new Cconnection(this, s, a));
		connection->process_events(EPOLLIN);
		if (connection->s() != INVALID_SOCKET)
		{
			m_connections.push_back(connection.release());
			m_epoll.ctl(EPOLL_CTL_ADD, m_connections.back().s(), EPOLLIN | EPOLLOUT | EPOLLPRI | EPOLLERR | EPOLLHUP | EPOLLET, &m_connections.back());
		}
	}
}

//插入peer
std::string Cserver::insert_peer(const Ctracker_input& v, bool udp, t_user* user)
{
	if (m_use_sql && m_config.m_log_announce)
	{
		m_announce_log_buffer += Csql_query(m_database, "(?,?,?,?,?,?,?,?,?,?),")
			.p(ntohl(v.m_ipa)).p(ntohs(v.m_port)).p(v.m_event).p(v.m_info_hash).p(v.m_peer_id).p(v.m_downloaded).p(v.m_left).p(v.m_uploaded).p(user ? user->uid : 0).p(time()).read();
	}
	if (!m_config.m_offline_message.empty())
		return m_config.m_offline_message;
	if (!m_config.m_anonymous_announce && !user)
		return bts_unregistered_torrent_pass;
	if (!m_config.m_auto_register && !file(v.m_info_hash))
		return bts_unregistered_torrent;

	// TorrentPier begin
	std::string xbt_error = "";
	if (v.m_left && user && !user->can_leech)
		/*if (xbt_error.empty())*/ xbt_error = bts_can_not_leech;
	t_file& file = m_files[v.m_info_hash];
	if (!file.ctime)
		file.ctime = time();
	//if (v.m_left && user && user->wait_time && file.ctime + user->wait_time > time() && !m_config.m_free_leech)
	if (v.m_left && user && user->wait_time && file.ctime + user->wait_time > time())
		/*return*/ if (xbt_error.empty()) xbt_error = bts_wait_time;

	t_peers::key_type peer_key = v.m_peer_id;
	t_peers::iterator i = file.peers.find(peer_key);
	if (i != file.peers.end())
	{
		if (i->second.xbt_error_empty)
		{
			(i->second.left ? file.leechers : file.seeders)--;
			if (t_user* old_user = find_user_by_uid(i->second.uid))
				(i->second.left ? old_user->incompletes : old_user->completes)--;
		}

		//统计种子的上传下载速度
		//file.speed_ul -= i->second.speed_ul, file.speed_dl -= i->second.speed_dl;
	}

	if (i != file.peers.end() && i->second.xbt_error_empty) { }
	//else if (v.m_left && user && user->torrents_limit && user->incompletes >= user->torrents_limit && !m_config.m_free_leech)
	else if (v.m_left && user && user->torrents_limit && user->incompletes >= user->torrents_limit)
	{
		/*return*/ if (xbt_error.empty()) xbt_error = bts_torrents_limit_reached;
	}
	//else if (v.m_left && user && user->peers_limit && !m_config.m_free_leech)
	else if (v.m_left && user && user->peers_limit)
	{
		int c = 0, a = 0;
		BOOST_FOREACH(t_peers::reference j, file.peers) {
			c += j.second.left && j.second.uid == user->uid && j.second.xbt_error_empty;
			a += j.second.uid == user->uid && j.second.xbt_error_empty;
		}
		if (c >= user->peers_limit || a >= user->peers_limit * 3)
			/*return*/ if (xbt_error.empty()) xbt_error = bts_peers_limit_reached;   //达到服务器最大负荷
	}

	//用于web统计
	long long downloaded = 0/*, downspeed = 0*/;
	long long uploaded = 0/*, upspeed = 0*/;
	//long long bonus_rate = 0;
	//long long ul_gdc = 0, ul_gdc_16k = 0;
	//int ul_gdc_count = 0, ul_16k_count = 0;

	//是否在使用ipv6
	bool ipv6set = v.m_ipv6set && (v.m_family == AF_INET6 || m_config.m_trust_ipv6);

	if (m_use_sql && user && file.fid)
	{
		/*
		if (user->uid == file.tor_poster_id)
		{
			bonus_rate = 1;
		}
		else if (!v.m_left && file.seeders<m_config.m_max_seeds_bonus)
		{
			bonus_rate = file.seeder/+1;
			bonus_rate *= bonus_rate;
		}
		*/

		//long long timespent = 0;
		if (i != file.peers.end()
			// && boost::equals(i->second.peer_id, v.m_peer_id)
			&& v.m_downloaded >= i->second.downloaded
			&& v.m_uploaded >= i->second.uploaded)
		{
			downloaded = v.m_downloaded - i->second.downloaded;
			uploaded = v.m_uploaded - i->second.uploaded;

			/*屏蔽开始
			if( downloaded > 100000000000ll || uploaded > 100000000000ll ) {
				downloaded = uploaded = 0; // anti-hack
				if (xbt_error.empty()) xbt_error = bts_banned_client;
			}
			timespent = time() - i->second.mtime;
			if (timespent*2 > m_config.m_announce_interval) // Fix, was 0
			{
				upspeed = uploaded / timespent;
				downspeed = downloaded / timespent;
			}
			ul_gdc_count = i->second.ul_gdc_count;
			ul_16k_count = i->second.ul_16k_count;
			ul_gdc_16k = i->second.ul_gdc_16k;
			if( uploaded && m_config.m_gdc )
			{
				ul_gdc_count++;
				long long block = 16384;
				if( (uploaded % block) == 0ll )
				{
					ul_16k_count++;
					if( ul_16k_count > 1 )
						ul_gdc_16k = gcd(uploaded, ul_gdc_16k);
					else
						ul_gdc_16k = uploaded;
				}
				if( ul_gdc_count == ul_16k_count )
					ul_gdc = ul_gdc_16k;
				else
				{
					if( ul_gdc_count > 1 )
						ul_gdc = gcd(uploaded, i->second.ul_gdc);
					else
						ul_gdc = uploaded;
				}
			}
			else
			{
				ul_gdc = i->second.ul_gdc;
			}
			屏蔽结束*/

			/*为phpbb XBT插件增加的部分，暂时屏蔽
			// TorrentPier: phpbb_bt_users_dl_status
			int new_status = v.m_left ? 1 : 2;
			if (new_status != i->second.dl_status && file.tor_topic_id) {
				Csql_query q(m_database, "(?,?,?,?),"); // topic_id,user_id,user_status,update_time
				q.p(file.tor_topic_id); // topic_id
				q.p(user->uid); // user_id
				q.p(new_status);
				q.p(time());
				m_users_dl_status_buffer += q.read();
				i->second.dl_status = new_status;
			}
			// TorrentPier: phpbb_bt_tor_dl_stat
			if (uploaded || downloaded) {
				Csql_query q(m_database, "(?,?,?,?,?,?),"); // torrent_id,user_id,attach_id,t_up_total,t_down_total
				q.p(file.fid); // torrent_id
				q.p(user->uid); // user_id
				q.p(file.tor_attach_id); // attach_id
				q.p(uploaded);
				q.p(m_config.m_free_leech ? 0 : (downloaded * file.dl_percent /100));
				q.p(bonus_rate ? uploaded/bonus_rate : 0);
				m_tor_dl_stat_buffer += q.read();
			}
			*/
		}

		//m_users_updates_buffer：将要写入到MYSQL中的数值的缓冲，字符串类型
		//Csql_query q(m_database, "(?,?,?,?,?,?,?,?,?,?, ?,?,?,?, ?,?,?,?),");
		Csql_query q(m_database, "(?,?,?,?,?,?,?,?,?,?,?,?),");

		int cleanup_interval = static_cast<int>(2.5 * m_config.m_announce_interval);
		if( cleanup_interval < 1800 ) cleanup_interval = 1800;

		/*
		q.p(file.fid); // torrent_id mediumint(8) unsigned NOT NULL default '0',
		q.p(v.m_peer_id); // peer_id char(20) binary NOT NULL default '',
		q.p(user->uid); // user_id mediumint(9) NOT NULL default '0',
		q.p(hex_encode(8, ntohl(v.m_ipa))); // ip char(8) binary NOT NULL default '0',
		q.p(const_memory_range(v.m_ipv6bin, ipv6set ? 16 : 0)); // ipv6 varchar(32)
		q.p(ntohs(v.m_port)); // port smallint(5) unsigned NOT NULL default '0',
		q.p(uploaded); // uploaded bigint(20) unsigned NOT NULL default '0',
		q.p(m_config.m_free_leech ? 0 : (downloaded * file.dl_percent /100)); // downloaded bigint(20) unsigned NOT NULL default '0',
		q.p(v.m_left ? (v.m_left>=file.tor_size ? 0 : ((file.tor_size-v.m_left)*100/file.tor_size)) : v.m_uploaded); // complete_percent bigint(20) unsigned NOT NULL default '0',
		q.p(v.m_left ? 0 : 1); // seeder tinyint(1) NOT NULL default '0',
		// last_stored_up bigint(20) unsigned NOT NULL default '0',
		// last_stored_down bigint(20) unsigned NOT NULL default '0',
		// stat_last_updated int(11) NOT NULL default '0',
		q.p(upspeed); // speed_up mediumint(8) unsigned NOT NULL default '0',
		q.p(downspeed); // speed_down mediumint(8) unsigned NOT NULL default '0',
		q.p(time()); // update_time int(11) NOT NULL default '0',
		q.p(v.m_event == Ctracker_input::e_stopped ? time() : time() + cleanup_interval); // expire_time int(11) NOT NULL default '0',
		// q.p(i == file.peers.end() ? 2 : i->second.listening ? 1 : 0); // port_open
		q.p(xbt_error);
		q.p( ul_16k_count*3 > ul_gdc_count*2 ? ul_gdc_16k : ul_gdc );
		q.p(ul_gdc_count);
		q.p(ul_16k_count);
		*/

		q.p(file.fid);                                          //种子的ID
		q.p(v.m_peer_id);                                       //peer的ID
		q.p(user->uid);                                         //用户的ID，可能为空
		q.p(hex_encode(8, ntohl(v.m_ipa)));                     //ipv4
		q.p(const_memory_range(v.m_ipv6bin, ipv6set ? 16 : 0)); //ipv6
		q.p(ntohs(v.m_port));                                   //端口
		q.p(uploaded);                                          //已上传，长整型
		q.p(downloaded);                                        //已下载，长整型
		q.p(v.m_left ? 0 : 1);                                  //是否是seeder
		q.p(time());                                            //进行更新时的时间
		q.p(v.m_event == Ctracker_input::e_stopped ? time() : time() + cleanup_interval); //过期时间
		q.p(xbt_error);                                         //事件信息

		m_files_users_updates_buffer += q.read();

		if (downloaded || uploaded)
		{
			/*
			Csql_query q(m_database, "(?,?,?,?,?,?),");
			q.p(m_config.m_free_leech ? 0 : (downloaded * file.dl_percent /100));
			q.p(uploaded);
			q.p(user->uid);
			q.p(bonus_rate ? uploaded/bonus_rate : 0);
			q.p(upspeed);
			q.p(downspeed);
			m_users_updates_buffer += q.read();
			*/
			m_users_updates_buffer += Csql_query(m_database, "(?,?,?),").p(downloaded).p(uploaded).p(user->uid).read();
		}
	}
	if (v.m_event == Ctracker_input::e_stopped)
		file.peers.erase(peer_key);
	else
	{
		t_peer& peer = file.peers[peer_key];
		peer.downloaded = v.m_downloaded;
		peer.left = v.m_left;
		// std::copy(v.m_peer_id.begin(), v.m_peer_id.end(), peer.peer_id.begin());
		peer.port = v.m_port;
		peer.uid = user ? user->uid : 0;
		peer.uploaded = v.m_uploaded;

		//file.speed_ul += ( peer.speed_ul = upspeed );   //种子的全局上传速度
		//file.speed_dl += ( peer.speed_dl = downspeed ); //种子的全局下载速度

		if (xbt_error.empty())
		{
			(peer.left ? file.leechers : file.seeders)++;
			if (user)
				(peer.left ? user->incompletes : user->completes)++;
		}

		peer.xbt_error_empty = xbt_error.empty();
		/*
		peer.ul_gdc = ul_gdc;
		peer.ul_gdc_16k = ul_gdc_16k;
		peer.ul_gdc_count = ul_gdc_count;
		peer.ul_16k_count = ul_16k_count;
		*/

		if (ipv6set) {
			peer.ipv6set = true;
			memcpy(peer.ipv6, v.m_ipv6bin, 16);
			m_stats.announced_with_ipv6++;
		}

		if (v.m_family == AF_INET || m_config.m_trust_ipv6) peer.host_ = v.m_ipa;

		peer.mtime = time();
	}
	if (v.m_event == Ctracker_input::e_completed)
		file.completed++/*, file.completed_inc++*/;

	// TorrentPier: Fill seeder_last_seen & last_seeder_uid fields
	/*
	if (user && !v.m_left)
	{
		file.tor_last_seeder_uid = user->uid;
		file.tor_seeder_last_seen = time();
	}
	*/

	(udp ? m_stats.announced_udp : m_stats.announced_http)++;
	file.dirty = true;
	return xbt_error;
	// TorrentPier end
}

//选择ipv4的peer列表
std::string Cserver::t_file::select_peers(const Ctracker_input& ti) const
{
	if (ti.m_event == Ctracker_input::e_stopped)
		return "";

	typedef std::vector<boost::array<char, 6> > t_candidates;

	t_candidates candidates;
	BOOST_FOREACH(t_peers::const_reference i, peers)
	{
		// TorrentPier begin
		if ((!ti.m_left && !i.second.left) || !i.second.xbt_error_empty || !i.second.host_
			|| boost::equals(i.first, ti.m_peer_id))
			continue;
		boost::array<char, 6> v;
		memcpy(&v.front(), &i.second.host_, 4);
		// TorrentPier end

		memcpy(&v.front() + 4, &i.second.port, 2);
		candidates.push_back(v);
	}
	size_t c = ti.m_num_want < 0 ? 50 : std::min(ti.m_num_want, 50); //返回的peer的数量
	std::string d;     //返回的peer列表是字符串（响应GET请求的回文是text/plain）
	d.reserve(300);
	if (candidates.size() > c)
	{
		while (c--)
		{
			int i = rand() % candidates.size();
			d.append(candidates[i].begin(), candidates[i].end());
			candidates[i] = candidates.back();
			candidates.pop_back();
		}
	}
	else
	{
		BOOST_FOREACH(t_candidates::reference i, candidates)
			d.append(i.begin(), i.end());
	}
	return d;
}

//选择ipv6的peer列表
// TorrentPier begin
std::string Cserver::t_file::select_peers6(const Ctracker_input& ti) const
{
	if (ti.m_event == Ctracker_input::e_stopped)
		return "";

	typedef std::vector<boost::array<char, 18> > t_candidates;

	t_candidates candidates;
	BOOST_FOREACH(t_peers::const_reference i, peers)
	{
		if ((!ti.m_left && !i.second.left) || !i.second.xbt_error_empty ||!i.second.ipv6set
			|| boost::equals(i.first, ti.m_peer_id))
			continue;

		boost::array<char, 18> v;
		memcpy(&v.front(), i.second.ipv6, 16);
		memcpy(&v.front() + 16, &i.second.port, 2);
		candidates.push_back(v);
	}
	size_t c = ti.m_num_want < 0 ? 50 : std::min(ti.m_num_want, 50);
	std::string d;
	d.reserve(900);
	if (candidates.size() > c)
	{
		while (c--)
		{
			int i = rand() % candidates.size();
			d.append(candidates[i].begin(), candidates[i].end());
			candidates[i] = candidates.back();
			candidates.pop_back();
		}
	}
	else
	{
		BOOST_FOREACH(t_candidates::reference i, candidates)
			d.append(i.begin(), i.end());
	}
	return d;
}
// TorrentPier end

//B编码的text/plain的部分回文（调用select_peers6()和select_peers()）
//种子数、下载数、完成数、请求时间间隔、种子列表
Cvirtual_binary Cserver::select_peers(const Ctracker_input& ti) const
{
	const t_file* f = file(ti.m_info_hash);
	if (!f)
		return Cvirtual_binary();
	// TorrentPier begin
	//if (ti.m_family == AF_INET6 && !m_config.m_trust_ipv6) {
	if (ti.m_family == AF_INET6 && m_config.m_trust_ipv6) {
		std::string peers6 = f->select_peers6(ti);
		return Cvirtual_binary((boost::format("d8:completei%de10:incompletei%de10:downloadedi%de8:intervali%de6:peers6%d:%se")
			% f->seeders % f->leechers % f->completed % config().m_announce_interval % peers6.size() % peers6).str());
	} else if (ti.m_family == AF_INET && !m_config.m_trust_ipv6) {
		std::string peers = f->select_peers(ti);
		return Cvirtual_binary((boost::format("d8:completei%de10:incompletei%de10:downloadedi%de8:intervali%de5:peers%d:%se")
			% f->seeders % f->leechers % f->completed % config().m_announce_interval % peers.size() % peers).str());
	} else {
		std::string peers = f->select_peers(ti);
		std::string peers6 = f->select_peers6(ti);
		return Cvirtual_binary((boost::format("d8:completei%de10:incompletei%de10:downloadedi%de8:intervali%de5:peers%d:%s6:peers6%d:%se")
			% f->seeders % f->leechers % f->completed % config().m_announce_interval % peers.size() % peers % peers6.size() % peers6).str());
	}
	// TorrentPier end
}

//清理失去响应的peer
void Cserver::t_file::clean_up(time_t t, Cserver& server)
{
	for (t_peers::iterator i = peers.begin(); i != peers.end(); )
	{
		if (i->second.mtime < t)
		{
			// TorrentPier begin
			if (i->second.xbt_error_empty)
			{
				(i->second.left ? leechers : seeders)--;
				if (t_user* user = server.find_user_by_uid(i->second.uid))
					(i->second.left ? user->incompletes : user->completes)--;
			}
			/*
			if (i->second.uid)
				server.m_files_users_updates_buffer += Csql_query(server.m_database, "(0,0,0,0,-1,0,-1,?,?),").p(fid).p(i->second.uid).read();
			*/
			//speed_ul -= i->second.speed_ul, speed_dl -= i->second.speed_dl;
			// TorrentPier end

			peers.erase(i++);
			dirty = true;
		}
		else
			i++;
	}
}

void Cserver::clean_up()
{
	// TorrentPier begin
	int cleanup_interval = static_cast<int>(2.5 * m_config.m_announce_interval);
	if( cleanup_interval < 1800 ) cleanup_interval = 1800;
	BOOST_FOREACH(t_files::reference i, m_files)
		i.second.clean_up(time() - cleanup_interval, *this);
	// TorrentPier end

	m_clean_up_time = time();
}

//响应刮请求
Cvirtual_binary Cserver::scrape(const Ctracker_input& ti)
{
	if (m_use_sql && m_config.m_log_scrape)
	{
		Csql_query q(m_database, "(?,?,?),");
		q.p(ntohl(ti.m_ipa));
		if (ti.m_info_hash.empty())
			q.p_raw("null");
		else
			q.p(ti.m_info_hash);
		q.p(time());
		m_scrape_log_buffer += q.read();
	}
	std::string d;
	d += "d5:filesd";
	if (ti.m_info_hashes.empty())
	{
		m_stats.scraped_full++;
		d.reserve(90 * m_files.size());
		BOOST_FOREACH(t_files::reference i, m_files)
		{
			if (i.second.leechers || i.second.seeders)
				d += (boost::format("20:%sd8:completei%de10:downloadedi%de10:incompletei%dee") % i.first % i.second.seeders % i.second.completed % i.second.leechers).str();
		}
	}
	else
	{
		m_stats.scraped_http++;
		BOOST_FOREACH(Ctracker_input::t_info_hashes::const_reference j, ti.m_info_hashes)
		{
			t_files::const_iterator i = m_files.find(j);
			if (i != m_files.end())
				d += (boost::format("20:%sd8:completei%de10:downloadedi%de10:incompletei%dee") % i->first % i->second.seeders % i->second.completed % i->second.leechers).str();
		}
	}
	d += "e";
	if (m_config.m_scrape_interval)
		d += (boost::format("5:flagsd20:min_request_intervali%dee") % m_config.m_scrape_interval).str();
	d += "e";
	return Cvirtual_binary(d);
}

//读取表xbt_deny_from_hosts
/***************
+-------+---------+------+-----+---------+-------+
| Field | Type    | Null | Key | Default | Extra |
+-------+---------+------+-----+---------+-------+
| begin | int(11) | NO   |     | NULL    |       |
| end   | int(11) | NO   |     | NULL    |       |
+-------+---------+------+-----+---------+-------+
***************/
void Cserver::read_db_deny_from_hosts()
{
	m_read_db_deny_from_hosts_time = time();
	if (!m_use_sql)
		return;
	try
	{
		Csql_result result = Csql_query(m_database, "select begin, end from ?").p_name(table_name(table_deny_from_hosts)).execute();
		BOOST_FOREACH(t_deny_from_hosts::reference i, m_deny_from_hosts)
			i.second.marked = true;
		for (Csql_row row; row = result.fetch_row(); )
		{
			t_deny_from_host& deny_from_host = m_deny_from_hosts[row[1].i()];
			deny_from_host.marked = false;
			deny_from_host.begin = row[0].i();
		}
		for (t_deny_from_hosts::iterator i = m_deny_from_hosts.begin(); i != m_deny_from_hosts.end(); )
		{
			if (i->second.marked)
				m_deny_from_hosts.erase(i++);
			else
				i++;
		}
	}
	catch (Cdatabase::exception&)
	{
	}
}


void Cserver::read_db_files()
{
	m_read_db_files_time = time();
	if (m_use_sql)
		read_db_files_sql();
	else if (!m_config.m_auto_register)
	{
		std::set<std::string> new_files;
		std::ifstream is("xbt_files.txt");
		std::string s;
		while (getline(is, s))
		{
			s = hex_decode(s);
			if (s.size() != 20)
				continue;
			m_files[s];
			new_files.insert(s);
		}
		for (t_files::iterator i = m_files.begin(); i != m_files.end(); )
		{
			if (new_files.find(i->first) == new_files.end())
				m_files.erase(i++);
			else
				i++;
		}
	}
}

/*******xbt_files********
v4表结构
+-----------+---------+------+-----+---------+----------------+
| Field     | Type    | Null | Key | Default | Extra          |
+-----------+---------+------+-----+---------+----------------+
| fid       | int(11) | NO   | PRI | NULL    | auto_increment |
| info_hash | blob    | NO   | UNI | NULL    |                |
| leechers  | int(11) | NO   |     | 0       |                |
| seeders   | int(11) | NO   |     | 0       |                |
| completed | int(11) | NO   |     | 0       |                |
| flags     | int(11) | NO   |     | 0       |                |
| mtime     | int(11) | NO   |     | NULL    |                |
| ctime     | int(11) | NO   |     | NULL    |                |
+-----------+---------+------+-----+---------+----------------+

v6表结构（旧）
+-----------+---------+------+-----+---------+----------------+
| Field     | Type    | Null | Key | Default | Extra          |
+-----------+---------+------+-----+---------+----------------+
| fid       | int(11) | NO   | PRI | NULL    | auto_increment |
| info_hash | blob    | NO   | UNI | NULL    |                |
| leechers  | int(11) | NO   |     | 0       |                |
| seeders   | int(11) | NO   |     | 0       |                |
| completed | int(11) | NO   |     | 0       |                |
| reg_time  | int(11) | NO   |     | NULL    |                |
| `size`
| attach_id
| topic_id
| seeder_last_seen
| last_seeder_uid
| speed_ul
| speed_dl
| poster_id
| column_files_dl_percent
+-----------+---------+------+-----+---------+----------------+

v6表结构（改）
+-----------+---------+------+-----+---------+----------------+
| Field     | Type    | Null | Key | Default | Extra          |
+-----------+---------+------+-----+---------+----------------+
| fid       | int(11) | NO   | PRI | NULL    | auto_increment |
| info_hash | blob    | NO   | UNI | NULL    |                |
| leechers  | int(11) | NO   |     | 0       |                |
| seeders   | int(11) | NO   |     | 0       |                |
| completed | int(11) | NO   |     | 0       |                |
| flags     | int(11) | NO   |     | 0       |                |
| reg_time  | int(11) | NO   |     | NULL    |                |
+-----------+---------+------+-----+---------+----------------+
*******xbt_files********/
//读取表xbt_files
void Cserver::read_db_files_sql()
{
	try
	{
		Csql_query q(m_database);
		if (!m_config.m_auto_register)
		{
			/*
			// XBT read only new torrents, so we need to mark deleted in "_del" table
			q = "select rpad(info_hash,20,' '), ?, is_del, dl_percent from "+table_name(table_files)+"_del";
			q.p_name(column_name(column_files_fid));
			Csql_result result = q.execute();
			for (Csql_row row; row = result.fetch_row(); )
			{
			//	if (row[0].size() != 20) continue;
				// fix
				t_files::iterator i = m_files.find(row[0].s());
				if (i != m_files.end())
				{
					if (row[2].i())
					{
						for (t_peers::iterator j = i->second.peers.begin(); j != i->second.peers.end(); j++)
						{
							t_user* user = j->second.uid ? find_user_by_uid(j->second.uid) : NULL;
							if (user && j->second.xbt_error_empty)
								(j->second.left ? user->incompletes : user->completes)--;
						}
						m_files.erase(i);
					} else {
						i->second.dl_percent = row[3].i();
					}
				}
				// fix
				q = "delete from "+table_name(table_files)+"_del where ? = ?";
				q.p_name(column_name(column_files_fid));
				q.p(row[1].i());
				q.execute();
			*/

			q = "select rpad(info_hash,20,' '), ? from ? where flags & 1";
			q.p_name(column_name(column_files_fid));
			q.p_name(table_name(table_files));
			Csql_result result = q.execute();
			for (Csql_row row; row = result.fetch_row(); )
			{
				t_files::iterator i = m_files.find(row[0].s());
				if (i != m_files.end())
				{
					for (t_peers::iterator j = i->second.peers.begin(); j != i->second.peers.end(); j++)
					{
						/*
						if (t_user* user = find_user_by_uid(j->second.uid))
							(j->second.left ? user->incompletes : user->completes)--;
						*/
						t_user* user = j->second.uid ? find_user_by_uid(j->second.uid) : NULL;
						if (user && j->second.xbt_error_empty)
							(j->second.left ? user->incompletes : user->completes)--;

					}
					m_files.erase(i);
				}
				q = "delete from "+table_name(table_files)+" where ? = ?";
				q.p_name(column_name(column_files_fid));
				q.p(row[1].i());
				q.execute();
			}
		}
		if (m_files.empty())
			m_database.query("update " + table_name(table_files) + " set "
				+ column_name(column_files_leechers) + " = 0, "
				+ column_name(column_files_seeders) + " = 0");
		else if (m_config.m_auto_register)
			return;
		q = "select rpad(info_hash,20,' '), ?, ?, reg_time from ? where ? >= ?";
		q.p_name(column_name(column_files_completed));
		q.p_name(column_name(column_files_fid));
		q.p_name(table_name(table_files));
		q.p_name(column_name(column_files_fid));
		q.p(m_fid_end);
		Csql_result result = q.execute();
		for (Csql_row row; row = result.fetch_row(); )
		{
			m_fid_end = std::max(m_fid_end, static_cast<int>(row[2].i()) + 1);
			if (row[0].size() != 20 || m_files.find(row[0].s()) != m_files.end())
				continue;
			t_file& file = m_files[row[0].s()];
			if (file.fid)
				continue;
			file.completed = row[1].i();
			file.dirty = false;
			file.fid = row[2].i();
			file.ctime = row[3].i();
		}
	}
	catch (Cdatabase::exception&)
	{
	}
}

//写xbt_files，此段落还需要修改
void Cserver::write_db_files()
{
	m_write_db_files_time = time();
	if (!m_use_sql)
		return;
	try
	{
		std::string buffer;
		BOOST_FOREACH(t_files::reference i, m_files)
		{
			t_file& file = i.second;
			if (!file.dirty)
				continue;
			if (!file.fid)
			{
				// TorrentPier begin
				Csql_query(m_database, "insert into ? (info_hash, reg_time) values (?, unix_timestamp())").p_name(table_name(table_files)).p(i.first).execute();
				// TorrentPier end

				file.fid = m_database.insert_id();
			}

			Csql_query q(m_database, "(?,?,?,?),");
			q.p(file.leechers);
			q.p(file.seeders);
			q.p(file.completed);
			q.p(file.fid);
			buffer += q.read();

			file.dirty = false;
		}
		if (!buffer.empty())
		{
			buffer.erase(buffer.size() - 1);
			/*
			m_database.query("insert into " + table_name(table_files) + " ("
				+ column_name(column_files_leechers) + ", "
				+ column_name(column_files_seeders) + ", "
				+ column_name(column_files_completed) + ", "
				+ column_name(column_files_fid)
				+ ", seeder_last_seen, last_seeder_uid, speed_ul, speed_dl) values "
				+ buffer
				+ " on duplicate key update speed_ul=values(speed_ul), speed_dl=values(speed_dl),"
				+ "  " + column_name(column_files_leechers) + " = values(" + column_name(column_files_leechers) + "),"
				+ "  " + column_name(column_files_seeders) + " = values(" + column_name(column_files_seeders) + "),"
				+ "  " + column_name(column_files_completed) + " = " + column_name(column_files_completed) + " + values(" + column_name(column_files_completed) + "),"
				+ "  seeder_last_seen = case when values(last_seeder_uid)>0 then values(seeder_last_seen) else seeder_last_seen end,"
				+ "  last_seeder_uid = case when values(last_seeder_uid)>0 then values(last_seeder_uid) else last_seeder_uid end"
			);
			*/
			m_database.query("insert into " + table_name(table_files) + " ("
				+ column_name(column_files_leechers) + ", "
				+ column_name(column_files_seeders) + ", "
				+ column_name(column_files_completed) + ", "
				+ column_name(column_files_fid)
				+ ") values "
				+ buffer
				+ " on duplicate key update"
				+ "  " + column_name(column_files_leechers) + " = values(" + column_name(column_files_leechers) + "),"
				+ "  " + column_name(column_files_seeders) + " = values(" + column_name(column_files_seeders) + "),"
				+ "  " + column_name(column_files_completed) + " = values(" + column_name(column_files_completed) + "),"
				+ "  reg_time = unix_timestamp()"
			);
		}
	}
	catch (Cdatabase::exception&)
	{
	}
	if (!m_announce_log_buffer.empty())
	{
		try
		{
			m_announce_log_buffer.erase(m_announce_log_buffer.size() - 1);
			m_database.query("insert delayed into " + table_name(table_announce_log) + " (ipa, port, event, info_hash, peer_id, downloaded, left0, uploaded, uid, mtime) values " + m_announce_log_buffer);
		}
		catch (Cdatabase::exception&)
		{
		}
		m_announce_log_buffer.erase();
	}
	if (!m_scrape_log_buffer.empty())
	{
		try
		{
			m_scrape_log_buffer.erase(m_scrape_log_buffer.size() - 1);
			m_database.query("insert delayed into " + table_name(table_scrape_log) + " (ipa, info_hash, mtime) values " + m_scrape_log_buffer);
		}
		catch (Cdatabase::exception&)
		{
		}
		m_scrape_log_buffer.erase();
	}
}

/*******xbt_user********
v4的表结构
+----------------------+---------------------+------+-----+---------+----------------+
| Field                | Type                | Null | Key | Default | Extra          |
+----------------------+---------------------+------+-----+---------+----------------+
| uid                  | int(11)             | NO   | PRI | NULL    | auto_increment |
| torrent_pass_version | int(11)             | NO   |     | 0       |                |
| downloaded           | bigint(20) unsigned | NO   |     | 0       |                |
| uploaded             | bigint(20) unsigned | NO   |     | 0       |                |
+----------------------+---------------------+------+-----+---------+----------------+
| name                 | char(8)             | NO   |     |         |                |
| pass                 | blob                | NO   |     |         |                |
| can_leech            | tinyint             | NO   |     | 1       |                |
| wait_time            | int                 | NO   |     | 0       |                |
| peers_limit          | int                 | NO   |     | 0       |                |
| torrents_limit       | int                 | NO   |     | 0       |                |
| torrent_pass         | char(32)            | NO   |     |         |                |
+----------------------+---------------------+------+-----+---------+----------------+

v6表结构（旧）
+----------------------+---------------------+------+-----+---------+----------------+
| Field                | Type                | Null | Key | Default | Extra          |
+----------------------+---------------------+------+-----+---------+----------------+
| uid                  | int(11)             | NO   | PRI | NULL    | auto_increment |
| auth_key
| [column_users_can_leech] as u_cl
| [column_users_torrents_limit] as u_tl
| u_down_total
| u_up_total
| u_bonus_total
| max_up_speed
| max_down_speed
+----------------------+---------------------+------+-----+---------+----------------+

v6表结构（改）
+----------------------+---------------------+------+-----+---------+----------------+
| Field                | Type                | Null | Key | Default | Extra          |
+----------------------+---------------------+------+-----+---------+----------------+
| uid                  | int(11)             | NO   | PRI | NULL    | auto_increment |
| u_down_total         | bigint(20) unsigned | NO   |     | 0       |                |
| u_up_total           | bigint(20) unsigned | NO   |     | 0       |                |
+----------------------+---------------------+------+-----+---------+----------------+
*******xbt_user********/
//读取表xbt_user
void Cserver::read_db_users()
{
	m_read_db_users_time = time();
	if (!m_use_sql)
		return;
	try
	{
		/*
		// TorrentPier begin
		Csql_query q(m_database, "select ?, auth_key, " + column_name(column_users_can_leech) + ", "
			+ column_name(column_users_torrents_limit) + " from ?");
		// TorrentPier end

		q.p_name(column_name(column_users_uid));
		q.p_name(table_name(table_users));
		*/
		Csql_query q(m_database, "select ?, u_down_total ,u_up_total from ?");
		q.p_name(column_name(column_users_uid));
		q.p_name(table_name(table_users));

		Csql_result result = q.execute();
		BOOST_FOREACH(t_users::reference i, m_users)
			i.second.marked = true;
		m_users_torrent_passes.clear();
		for (Csql_row row; row = result.fetch_row(); )
		{
			//构建用户
			t_user& user = m_users[row[0].i()];
			user.marked = false;

			/*
			user.uid = row[0].i();
			user.wait_time = 0;
			user.torrents_limit = row[3].i();
			user.peers_limit = 2; // # of IP addresses user can leech from
			user.can_leech = row[2].i();
			//由auth_key作为关键字插入用户到列表
			if (row[1].size())
				m_users_torrent_passes[row[1].s()] = &user;
			*/

			user.uid = row[0].i();
			user.wait_time = 0;
			user.torrents_limit = 0;
			user.peers_limit = 0;
			user.can_leech = true;
			/*
			if (row[1].size())
				m_users_torrent_passes[row[1].s()] = &user;
			*/
		}
		for (t_users::iterator i = m_users.begin(); i != m_users.end(); )
		{
			if (i->second.marked)
				m_users.erase(i++);
			else
				i++;
		}
	}
	catch (Cdatabase::exception&)
	{
	}
}

void Cserver::write_db_users()
{
	m_write_db_users_time = time();
	if (!m_use_sql)
		return;
	if (!m_files_users_updates_buffer.empty())
	{
		m_files_users_updates_buffer.erase(m_files_users_updates_buffer.size() - 1); //去掉最后一个逗号
		try
		{
			/*
			m_database.query("insert into " + table_name(table_files_users)
				+ " (torrent_id, peer_id, user_id, ip, ipv6, port, uploaded, downloaded, complete_percent, seeder, speed_up, speed_down, update_time, expire_time, xbt_error, ul_gdc, ul_gdc_c, ul_16k_c) values "
				+ m_files_users_updates_buffer
				+ " on duplicate key update"
				+ "  torrent_id = values(torrent_id),"
				+ "  peer_id = values(peer_id),"
				+ "  user_id = values(user_id),"
				+ "  ip = values(ip), ipv6 = values(ipv6),"
				+ "  port = values(port),"
				+ "  uploaded = uploaded + values(uploaded),"
				+ "  downloaded = downloaded + values(downloaded),"
				+ "  complete_percent = values(complete_percent),"
				+ "  seeder = values(seeder),"
				+ "  speed_up = values(speed_up),"
				+ "  speed_down = values(speed_down),"
				+ "  update_time = values(update_time),"
				+ "  expire_time = values(expire_time),"
				+ "  xbt_error=values(xbt_error), ul_gdc=values(ul_gdc), ul_gdc_c=values(ul_gdc_c), ul_16k_c=values(ul_16k_c),"
				+ " last_stored_up=uploaded,last_stored_down=downloaded,stat_last_updated=values(update_time)");
			*/
			m_database.query("insert into " + table_name(table_files_users)
				+ " (torrent_id, peer_id, user_id, ip, ipv6, port, uploaded, downloaded, seeder, update_time, expire_time, xbt_error) values "
				+ m_files_users_updates_buffer
				+ " on duplicate key update"
				+ "  torrent_id = values(torrent_id),"
				+ "  peer_id = values(peer_id),"
				+ "  user_id = values(user_id),"
				+ "  ip = values(ip), ipv6 = values(ipv6),"
				+ "  port = values(port),"
				+ "  uploaded = uploaded + values(uploaded),"       /*累加*/
				+ "  downloaded = downloaded + values(downloaded)," /*累加*/
				+ "  seeder = values(seeder),"
				+ "  update_time = values(update_time),"
				+ "  expire_time = values(expire_time),"
				+ "  xbt_error = values(xbt_error)");
		}
		catch (Cdatabase::exception&)
		{
		}
		m_files_users_updates_buffer.erase();
	}
	if (!m_users_updates_buffer.empty())
	{
		m_users_updates_buffer.erase(m_users_updates_buffer.size() - 1); //去掉最后一个逗号
		try
		{
			/*
			m_database.query("insert into " + table_name(table_users) + " (u_down_total, u_up_total, " + column_name(column_users_uid) + ", u_bonus_total, max_up_speed, max_down_speed) values "
				+ m_users_updates_buffer
				+ " on duplicate key update"
				+ "  u_down_total = u_down_total + values(u_down_total),"
				+ "  u_up_total = u_up_total + values(u_up_total),"
				+ "  u_bonus_total = u_bonus_total + values(u_bonus_total),"
				+ "  max_up_speed = GREATEST(max_up_speed, values(max_up_speed)),"
				+ "  max_down_speed = GREATEST(max_down_speed, values(max_down_speed))");
			*/
			m_database.query("insert into " + table_name(table_users) + " (u_down_total, u_up_total, " + column_name(column_users_uid) + ") values "
				+ m_users_updates_buffer
				+ " on duplicate key update"
				+ "  u_down_total = u_down_total + values(u_down_total),"
				+ "  u_up_total = u_up_total + values(u_up_total)");
		}
		catch (Cdatabase::exception&)
		{
		}
		m_users_updates_buffer.erase();
	}
	//phpbb集成部分
	/*
	if (!m_users_dl_status_buffer.empty())
	{
		m_users_dl_status_buffer.erase(m_users_dl_status_buffer.size() - 1);
		try
		{
			m_database.query("insert into phpbb_bt_users_dl_status(topic_id,user_id,user_status,update_time) values"
				+ m_users_dl_status_buffer
				+ " on duplicate key update"
				+ "  user_status = values(user_status),"
				+ "  update_time = values(update_time)");
		}
		catch (Cdatabase::exception&)
		{
		}
		m_users_dl_status_buffer.erase();
	}
	*/
	/*
	if (!m_tor_dl_stat_buffer.empty())
	{
		m_tor_dl_stat_buffer.erase(m_tor_dl_stat_buffer.size() - 1);
		try
		{
			m_database.query("insert into phpbb_bt_tor_dl_stat(torrent_id,user_id,attach_id,t_up_total,t_down_total,t_bonus_total) values"
				+ m_tor_dl_stat_buffer
				+ " on duplicate key update"
				+ "  t_up_total = t_up_total + values(t_up_total),"
				+ "  t_bonus_total = t_bonus_total + values(t_bonus_total),"
				+ "  t_down_total = t_down_total + values(t_down_total)");
		}
		catch (Cdatabase::exception&)
		{
		}
		m_tor_dl_stat_buffer.erase();
	}
	*/
}

void Cserver::read_config()
{
	if (m_use_sql)
	{
		try
		{
			Csql_result result = m_database.query("select name, value from " + table_name(table_config) + " where value is not null");
			Cconfig config;
			for (Csql_row row; row = result.fetch_row(); )
			{
				if (config.set(row[0].s(), row[1].s()))
					std::cerr << "unknown config name: " << row[0].s() << std::endl;
			}
			config.load(m_conf_file);
			if (config.m_torrent_pass_private_key.empty())
			{
				config.m_torrent_pass_private_key = generate_random_string(27);
				Csql_query(m_database, "insert into xbt_config (name, value) values ('torrent_pass_private_key', ?)").p(config.m_torrent_pass_private_key).execute();
			}
			m_config = config;
		}
		catch (Cdatabase::exception&)
		{
		}
	}
	else
	{
		Cconfig config;
		if (!config.load(m_conf_file))
			m_config = config;
	}

	// TorrentPier begin
	if (m_config.m_listen_ipas.empty())
		m_config.m_listen_ipas.insert("*");
	if (m_config.m_listen_ports.empty())
		m_config.m_listen_ports.insert("2710");  //假如监听端口未指定，则加入2710端口
	// TorrentPier end

	m_read_config_time = time();
}

void Cserver::t_file::debug(std::ostream& os) const
{
	BOOST_FOREACH(t_peers::const_reference i, peers)
	{
		// TorrentPier begin
		os << "<tr><td>" + Csocket::inet_ntoa(i.second.host_)
			<< "<td align=right>" << (i.second.ipv6set ? hex_encode(const_memory_range(i.second.ipv6,16)) : "")
			// TorrentPier end

			<< "<td align=right>" << ntohs(i.second.port)
			<< "<td align=right>" << i.second.uid
			<< "<td align=right>" << i.second.left
			<< "<td align=right>" << ::time(NULL) - i.second.mtime

			// TorrentPier begin
			<< "<td>" << hex_encode(const_memory_range(i.first.c_str(), 20));
			// TorrentPier end
	}
}

std::string Cserver::debug(const Ctracker_input& ti) const
{
	std::ostringstream os;
	os << "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\"><meta http-equiv=refresh content=60><title>XBT Tracker</title>";
	int leechers = 0;
	int seeders = 0;
	int torrents = 0;
	os << "<table>";
	if (ti.m_info_hash.empty())
	{
		BOOST_FOREACH(t_files::const_reference i, m_files)
		{
			if (!i.second.leechers && !i.second.seeders)
				continue;
			leechers += i.second.leechers;
			seeders += i.second.seeders;
			torrents++;
			os << "<tr><td align=right>" << i.second.fid
				<< "<td><a href=\"?info_hash=" << uri_encode(i.first) << "\">" << hex_encode(i.first) << "</a>"
				<< "<td>" << (i.second.dirty ? '*' : ' ')
				<< "<td align=right>" << i.second.leechers
				<< "<td align=right>" << i.second.seeders;
		}
	}
	else
	{
		t_files::const_iterator i = m_files.find(ti.m_info_hash);
		if (i != m_files.end())
			i->second.debug(os);
	}
	os << "</table>";
	return os.str();
}

//状态信息响应（http://localhost:2710/status）
std::string Cserver::statistics() const
{
	std::ostringstream os;
	os << "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\"><meta http-equiv=refresh content=60><title>XBT Tracker</title>";
	int leechers = 0;
	int seeders = 0;
	int torrents = 0;
	BOOST_FOREACH(t_files::const_reference i, m_files)
	{
		leechers += i.second.leechers;
		seeders += i.second.seeders;
		torrents += i.second.leechers || i.second.seeders;
	}
	time_t t = time();
	os << "<table><tr><td>leechers<td align=right>" << leechers
		<< "<tr><td>seeders<td align=right>" << seeders
		<< "<tr><td>peers<td align=right>" << leechers + seeders
		<< "<tr><td>torrents<td align=right>" << torrents
		<< "<tr><td>"
		<< "<tr><td>accepted tcp<td align=right>" << m_stats.accepted_tcp

		// TorrentPier begin
		<< "<tr><td>accepted tcp4<td align=right>" << m_stats.accepted_tcp4 << "<td align=right>" << m_stats.accepted_tcp4 * 100 / m_stats.accepted_tcp << " %"
		<< "<tr><td>accepted tcp6<td align=right>" << m_stats.accepted_tcp6 << "<td align=right>" << m_stats.accepted_tcp6 * 100 / m_stats.accepted_tcp << " %"
		// TorrentPier end

		<< "<tr><td>rejected tcp<td align=right>" << m_stats.rejected_tcp
		<< "<tr><td>announced<td align=right>" << m_stats.announced();
	if (m_stats.announced())
	{
		os << "<tr><td>announced http <td align=right>" << m_stats.announced_http << "<td align=right>" << m_stats.announced_http * 100 / m_stats.announced() << " %"
			<< "<tr><td>announced udp<td align=right>" << m_stats.announced_udp << "<td align=right>" << m_stats.announced_udp * 100 / m_stats.announced() << " %"

			// TorrentPier begin
			<< "<tr><td>with &amp;ipv6=<td align=right>" << m_stats.announced_with_ipv6 << "<td align=right>" << m_stats.announced_with_ipv6 * 100 / m_stats.announced() << " %";
			// TorrentPier end
	}
	os << "<tr><td>scraped full<td align=right>" << m_stats.scraped_full
		<< "<tr><td>scraped<td align=right>" << m_stats.scraped();
	if (m_stats.scraped())
	{
		os << "<tr><td>scraped http<td align=right>" << m_stats.scraped_http << "<td align=right>" << m_stats.scraped_http * 100 / m_stats.scraped() << " %"
			<< "<tr><td>scraped udp<td align=right>" << m_stats.scraped_udp << "<td align=right>" << m_stats.scraped_udp * 100 / m_stats.scraped() << " %";
	}
	os << "<tr><td>"
		<< "<tr><td>up time<td align=right>" << duration2a(time() - m_stats.start_time)
		<< "<tr><td>"
		<< "<tr><td>anonymous connect<td align=right>" << m_config.m_anonymous_connect
		<< "<tr><td>anonymous announce<td align=right>" << m_config.m_anonymous_announce
		<< "<tr><td>anonymous scrape<td align=right>" << m_config.m_anonymous_scrape
		<< "<tr><td>auto register<td align=right>" << m_config.m_auto_register
		<< "<tr><td>full scrape<td align=right>" << m_config.m_full_scrape

		// TorrentPier begin
		//<< "<tr><td>free leech<td align=right>" << m_config.m_free_leech
		<< "<tr><td>announce interval<td align=right>" << m_config.m_announce_interval
		// TorrentPier end

		<< "<tr><td>read config time<td align=right>" << t - m_read_config_time << " / " << m_config.m_read_config_interval
		<< "<tr><td>clean up time<td align=right>" << t - m_clean_up_time << " / " << m_config.m_clean_up_interval

		// TorrentPier begin
		<< "<tr><td>read db files time<td align=right>" << t - m_read_db_files_time << " / " << m_config.m_read_files_interval;
		// TorrentPier end

	if (m_use_sql)
	{
		os << "<tr><td>read db users time<td align=right>" << t - m_read_db_users_time << " / " << m_config.m_read_db_interval
			<< "<tr><td>write db files time<td align=right>" << t - m_write_db_files_time << " / " << m_config.m_write_db_interval
			<< "<tr><td>write db users time<td align=right>" << t - m_write_db_users_time << " / " << m_config.m_write_db_interval;
	}
	os << "</table>";
	return os.str();
}

/*
Cserver::t_user* Cserver::find_user_by_name(const std::string& v)
{
	t_users_names::const_iterator i = m_users_names.find(v);
	return i == m_users_names.end() ? NULL : i->second;
}
*/

Cserver::t_user* Cserver::find_user_by_torrent_pass(const std::string& v, const std::string& info_hash)
{
	/*
	if (t_user* user = find_user_by_uid(read_int(4, hex_decode(v.substr(0, 8)))))
	{
		if (v.size() >= 8 && Csha1((boost::format("%s %d %d %s") % m_config.m_torrent_pass_private_key % user->torrent_pass_version % user->uid % info_hash).str()).read().substr(0, 12) == hex_decode(v.substr(8)))
			return user;
	}
	*/

	//通过auth_key在m_users_torrent_passes中查找用户，m_users_torrent_passes通过读取数据库生成
	t_users_torrent_passes::const_iterator i = m_users_torrent_passes.find(v);
	return i == m_users_torrent_passes.end() ? NULL : i->second;  //如果没找到user则返回一个空指针，找到则返回一个user
}

Cserver::t_user* Cserver::find_user_by_uid(int v)
{
	t_users::iterator i = m_users.find(v);
	return i == m_users.end() ? NULL : &i->second;
}

void Cserver::sig_handler(int v)
{
	switch (v)
	{
	case SIGTERM:
		g_sig_term = true;
		break;
	}
}

void Cserver::term()
{
	g_sig_term = true;
}

std::string Cserver::column_name(int v) const
{
	switch (v)
	{
	case column_files_completed:
		return m_config.m_column_files_completed;
	case column_files_leechers:
		return m_config.m_column_files_leechers;
	case column_files_seeders:
		return m_config.m_column_files_seeders;
	case column_files_fid:
		return m_config.m_column_files_fid;
	case column_users_uid:
		return m_config.m_column_users_uid;

	// TorrentPier begin
	/*屏蔽开始
	case column_files_dl_percent:
		return m_config.m_column_files_dl_percent;
	case column_users_can_leech:
		return m_config.m_column_users_can_leech;
	case column_users_torrents_limit:
		return m_config.m_column_users_torrents_limit;
	屏蔽结束*/
	// TorrentPier end

	}
	assert(false);
	return "";
}

//返回MYSQL中的表名，前缀一般是xbt_，共7个表
/***************
xbt_announce_log（日志）
xbt_config（配置）
xbt_deny_from_host（封禁列表）
xbt_files（种子）
xbt_files_users（正在下载或上传某种子(fid)的用户）
xbt_scrape_log（刮日志）
xbt_users（用户，或者说是在经过注册的上传种子的用户）
***************/
std::string Cserver::table_name(int v) const
{
	switch (v)
	{
	case table_announce_log:
		return m_config.m_table_announce_log.empty() ? m_table_prefix + "announce_log" : m_config.m_table_announce_log;
	case table_config:
		return m_table_prefix + "config";
	case table_deny_from_hosts:
		return m_config.m_table_deny_from_hosts.empty() ? m_table_prefix + "deny_from_hosts" : m_config.m_table_deny_from_hosts;
	case table_files:
		return m_config.m_table_files.empty() ? m_table_prefix + "files" : m_config.m_table_files;
	case table_files_users:
		return m_config.m_table_files_users.empty() ? m_table_prefix + "files_users" : m_config.m_table_files_users;
	case table_scrape_log:
		return m_config.m_table_scrape_log.empty() ? m_table_prefix + "scrape_log" : m_config.m_table_scrape_log;
	case table_users:
		return m_config.m_table_users.empty() ? m_table_prefix + "users" : m_config.m_table_users;
	}
	assert(false);
	return "";
}

/***************
v4、v6一致的表
xbt_announce_log：id, ipa, port, event, info_hash, peer_id, downloaded, left0, uploaded, uid, mtime
xbt_config：name, value
xbt_deny_from_host：begin, end
xbt_scrape_log：id, ipa, info_hash, uid, mtime

xbt_files
v4：fid, info_hash, leechers, seeders, completed, flags, mtime, ctime
v6改：fid, info_hash, leechers, seeders, completed, flags, reg_time
v6旧：fid, info_hash, leechers, seeders, completed, reg_time, `size`, attach_id, topic_id, seeder_last_seen, last_seeder_uid, speed_ul, speed_dl, poster_id, [column_files_dl_percent]

xbt_files_users
v4：fid, uid, active, announced, completed, downloaded, `left`, uploaded, mtime
v6改：torrent_id, peer_id, user_id, ip, ipv6, port, uploaded, downloaded, seeder, update_time, expire_time, xbt_error
v6旧：torrent_id, peer_id, user_id, ip, ipv6, port, uploaded, downloaded, complete_percent, seeder, speed_up, speed_down, update_time, expire_time, ul_gdc, ul_gdc_c, ul_16k_c, xbt_error

xbt_users
v4：uid, torrent_pass_version, downloaded, uploaded
v6改：uid, u_down_total, u_up_total
v6旧：uid, auth_key, [column_users_can_leech] as u_cl, [column_users_torrents_limit] as u_tl,u_down_total, u_up_total, u_bonus_total, max_up_speed, max_down_speed
***************/
int Cserver::test_sql()
{
	if (!m_use_sql)
		return 0;
	try
	{
		mysql_get_server_version(&m_database.handle());
		m_database.query("select id, ipa, port, event, info_hash, peer_id, downloaded, left0, uploaded, uid, mtime from " + table_name(table_announce_log) + " where 0");
		m_database.query("select name, value from " + table_name(table_config) + " where 0");
		m_database.query("select begin, end from " + table_name(table_deny_from_hosts) + " where 0");
		m_database.query("select id, ipa, info_hash, uid, mtime from " + table_name(table_scrape_log) + " where 0");

		// TorrentPier begin
		/*
		m_database.query("select torrent_id, peer_id, user_id, ip, ipv6, port, uploaded, downloaded, complete_percent, seeder, speed_up, speed_down, update_time, expire_time, ul_gdc, ul_gdc_c, ul_16k_c from " + table_name(table_files_users) + " where 0"); // Note: `port_open` is not used any more
		m_database.query("select " + column_name(column_users_uid) + ", auth_key, "
                  + column_name(column_users_can_leech) + " as u_cl, " + column_name(column_users_torrents_limit)
                  + " as u_tl, u_down_total, u_up_total, u_bonus_total, max_up_speed, max_down_speed from " + table_name(table_users) + " where 0");
		m_database.query("select " + column_name(column_files_fid) + ", info_hash, "
                  + column_name(column_files_leechers) + ", " + column_name(column_files_seeders)
                  + ", reg_time, `size`, attach_id, topic_id, seeder_last_seen, last_seeder_uid, speed_ul, speed_dl, poster_id, "
                  + column_name(column_files_dl_percent) + " from " + table_name(table_files) + " where 0");
		// TorrentPier: Files deletion table = table_name(table_files) + "_del" suffix
		m_database.query("select rpad(info_hash,20,' '), " + column_name(column_files_fid)
                  + ", is_del, dl_percent from " + table_name(table_files) + "_del where 0");
		m_database.query("select topic_id,user_id,user_status,update_time from phpbb_bt_users_dl_status where 0");
		m_database.query("select torrent_id,user_id,attach_id,t_up_total,t_down_total,t_bonus_total from phpbb_bt_tor_dl_stat where 0");
		*/
		// TorrentPier end

		m_database.query("select torrent_id, peer_id, user_id, ip, ipv6, port, uploaded, downloaded, seeder, update_time, expire_time, xbt_error from " + table_name(table_files_users) + " where 0"); // Note: `port_open` is not used any more
		m_database.query("select " + column_name(column_users_uid)
                  + " u_down_total, u_up_total from " + table_name(table_users) + " where 0");
		m_database.query("select " + column_name(column_files_fid) + ", info_hash, "
                  + column_name(column_files_leechers) + ", " + column_name(column_files_seeders)
                  + ", completed, flags, reg_time"
                  + " from " + table_name(table_files) + " where 0");

		m_read_users_can_leech = m_database.query("show columns from " + table_name(table_users) + " like 'can_leech'");
		m_read_users_peers_limit = m_database.query("show columns from " + table_name(table_users) + " like 'peers_limit'");
		//m_read_users_name_pass = m_database.query("show columns from " + table_name(table_users) + " like 'pass'");
		m_read_users_torrent_pass = m_database.query("show columns from " + table_name(table_users) + " like 'torrent_pass'");
		m_read_users_torrent_pass_version = m_database.query("show columns from " + table_name(table_users) + " like 'torrent_pass_version'");
		m_read_users_torrents_limit = m_database.query("show columns from " + table_name(table_users) + " like 'torrents_limit'");
		m_read_users_wait_time = m_database.query("show columns from " + table_name(table_users) + " like 'wait_time'");
		return 0;
	}
	catch (Cdatabase::exception&)
	{
	}
	return 1;
}
