#pragma once

#include "config.h"
#include "connection.h"
#include "epoll.h"
#include "stats.h"
#include "tcp_listen_socket.h"
#include "tracker_input.h"
#include "udp_listen_socket.h"
#include <boost/array.hpp>
#include <boost/ptr_container/ptr_list.hpp>
#include <map>
#include <sql/database.h>
#include <virtual_binary.h>

//tracker�ṩ�Ự������
class Cserver
{
public:
	// TorrentPier begin
	typedef std::string peer_key_c;  //��peer_key_c�����˼򻯴���
	// TorrentPier end

	//�ṹ��peer
	struct t_peer
	{
		//Ĭ�ϵĳ�ʼ����ʽ
		t_peer()
		{
			mtime = 0;

			// TorrentPier begin
			dl_status = 0; // 1 = downloading, 2 = complete
			ipv6set = false;
			host_ = 0;
			// TorrentPier end
		}

		long long downloaded;
		long long uploaded;
		time_t mtime;
		int uid;
		short port;               //�˿ڣ�2�ֽ�
		bool left;
		//boost::array<char, 20> peer_id;

		//needmodified_b
		long long speed_dl;       //�����ٶ�
		long long speed_ul;       //�ϴ��ٶ�
		int dl_status;            //״̬
		bool xbt_error_empty;
		// Upload Greatest Common Divisor
		//long long ul_gdc, ul_gdc_16k;
		//int ul_gdc_count, ul_16k_count;
		//needmodified_e

		bool ipv6set;              //�Ƿ�ʹ��ipv6
		// boost::array<char, 16> ipv6;
		char ipv6[16];             //ipv6��ַ
		int host_;
	};

	typedef std::map<peer_key_c, t_peer> t_peers; //map��STL����������һ��һ��ӳ��

	struct t_deny_from_host
	{
		unsigned int begin;
		bool marked;
	};

	//�ṹ��tracker�ϵ�torrent������
	struct t_file
	{
		void clean_up(time_t t, Cserver&);
		void debug(std::ostream&) const;
		std::string select_peers(const Ctracker_input&) const;

		// TorrentPier begin
		std::string select_peers6(const Ctracker_input&) const;    //ѡ��peer��ipv6��
		// TorrentPier end

		//Ĭ�ϵĹ��췽ʽ
		t_file()
		{
			completed = 0;
			dirty = true;
			fid = 0;
			leechers = 0;
			seeders = 0;

			//needmodified_b
			/*
			completed_inc = 0;
			tor_size = 0;
			tor_attach_id = tor_topic_id = 0;
			tor_seeder_last_seen = 0;
			tor_last_seeder_uid = tor_poster_id = 0;
			speed_dl = speed_ul = 0;
			dl_percent = 100;
			*/
			//needmodified_e
		}

		t_peers peers;   //peer�б�
		time_t ctime;    //��������ʱ�䣨��1970��1��1��0ʱ0��0�����������
		int completed;   //�����
		int fid;         //����ID����Mysql��������
		int leechers;    //��������
		int seeders;     //���Ӹ���
		bool dirty;

		//needmodified_b         
		//��v4�����ĳ�Ա����web�������
		/*
		int completed_inc;
		long long tor_size;                      //���ӵĴ�С
		int tor_attach_id, tor_topic_id;         //���Ӹ�����ID���������ӵ�ID
		time_t tor_seeder_last_seen;             //������ֵ�ʱ��
		int tor_last_seeder_uid, tor_poster_id;  //������ֵ�seeder��ID�����ӷ����˵�ID
		long long speed_dl, speed_ul;            //ȫ�������ϴ��ٶ�
		int dl_percent;
		*/
		//needmodified_e
	};

	struct t_user
	{
		t_user()
		{
			can_leech = true;
			completes = 0;
			incompletes = 0;
			peers_limit = 0;
			torrent_pass_version = 0;
			torrents_limit = 0;
			wait_time = 0;
		}

		bool can_leech;
		bool marked;
		int uid;
		int completes;
		int incompletes;
		int peers_limit;
		int torrent_pass_version;
		int torrents_limit;
		int wait_time;
		//std::string pass;    //deletedpara
	};

	typedef std::map<std::string, t_file> t_files;                        //���ӵ�hashֵ���ַ������ͣ���Ϊ�ؼ���
	typedef std::map<unsigned int, t_deny_from_host> t_deny_from_hosts;   //
	typedef std::map<int, t_user> t_users;                                //�û��б���uid�������ؼ�����uid
	//typedef std::map<std::string, t_user*> t_users_names;               //deletedpara
	typedef std::map<std::string, t_user*> t_users_torrent_passes;        //�û��б���auth_key�������ؼ�����auth_key

	int test_sql();
	void accept(const Csocket&);
	//t_user* find_user_by_name(const std::string&);                      //deletedfun
	t_user* find_user_by_torrent_pass(const std::string&, const std::string& info_hash);
	t_user* find_user_by_uid(int);
	void read_config();
	void write_db_files();
	void write_db_users();
	void read_db_deny_from_hosts();
	void read_db_files();
	void read_db_files_sql();
	void read_db_users();
	void clean_up();
	std::string insert_peer(const Ctracker_input&, bool udp, t_user*);
	std::string debug(const Ctracker_input&) const;
	std::string statistics() const;
	Cvirtual_binary select_peers(const Ctracker_input&) const;
	Cvirtual_binary scrape(const Ctracker_input&);
	int run();
	static void term();
	Cserver(Cdatabase&, const std::string& table_prefix, bool use_sql, const std::string& conf_file);

	const t_file* file(const std::string& id) const
	{
		t_files::const_iterator i = m_files.find(id);
		return i == m_files.end() ? NULL : &i->second;
	}

	const Cconfig& config() const
	{
		return m_config;
	}

	long long secret() const
	{
		return m_secret;
	}

	Cstats& stats()
	{
		return m_stats;
	}

	time_t time() const
	{
		return m_time;
	}
private:
	enum
	{
		column_files_completed,
		column_files_fid,
		column_files_leechers,
		column_files_seeders,
		column_users_uid,
		table_announce_log,
		table_config,
		table_deny_from_hosts,
		table_files,
		table_files_users,
		table_scrape_log,
		table_users,

		// TorrentPier begin
		/*��ʼ����
		column_files_dl_percent,
		column_users_can_leech,
		column_users_torrents_limit,
		���ν���*/
		// TorrentPier end
	};

	typedef boost::ptr_list<Cconnection> t_connections;
	typedef std::list<Ctcp_listen_socket> t_tcp_sockets;
	typedef std::list<Cudp_listen_socket> t_udp_sockets;

	static void sig_handler(int v);
	std::string column_name(int v) const;
	std::string table_name(int) const;

	Cconfig m_config;
	Cstats m_stats;
	bool m_read_users_can_leech;
	//bool m_read_users_name_pass;                 //deletedpara
	bool m_read_users_peers_limit;                 //������չ��������ȥ��
	bool m_read_users_torrent_pass;                //������չ��������ȥ��
	bool m_read_users_torrent_pass_version;        //������չ��������ȥ��
	bool m_read_users_torrents_limit;              //������չ��������ȥ��
	bool m_read_users_wait_time;                   //������չ��������ȥ��
	bool m_use_sql;
	time_t m_clean_up_time;
	time_t m_read_config_time;
	time_t m_read_db_deny_from_hosts_time;
	time_t m_read_db_files_time;
	time_t m_read_db_users_time;
	time_t m_time;
	time_t m_write_db_files_time;
	time_t m_write_db_users_time;
	int m_fid_end;
	long long m_secret;
	t_connections m_connections;
	Cdatabase& m_database;
	Cepoll m_epoll;
	t_deny_from_hosts m_deny_from_hosts;
	t_files m_files;
	t_users m_users;
	//t_users_names m_users_names;                 //deletedpara
	t_users_torrent_passes m_users_torrent_passes; //��auth_key�������û��б�
	std::string m_announce_log_buffer;             //buffer��д�뵽MYSQL��ֵ�Ļ���
	std::string m_conf_file;                       //
	std::string m_files_users_updates_buffer;      //
	std::string m_scrape_log_buffer;               //
	std::string m_table_prefix;                    //
	std::string m_users_updates_buffer;            //

	// TorrentPier begin
	/*
	std::string m_users_dl_status_buffer;
	std::string m_tor_dl_stat_buffer;
	*/
	// TorrentPier end
};
