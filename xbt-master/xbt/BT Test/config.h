#pragma once

#include "config_base.h"

class Cconfig: public Cconfig_base
{
public:
	std::ostream& operator<<(std::ostream&) const;
	Cconfig();
	Cconfig(const Cconfig&);
	const Cconfig& operator=(const Cconfig&);

	bool m_bind_before_connect;
	bool m_log_peer_connect_failures;
	bool m_log_peer_connection_closures;
	bool m_log_peer_recv_failures;
	bool m_log_peer_send_failures;
	bool m_log_piece_valid;
	bool m_send_stop_event;
	bool m_upnp;
	int m_admin_port;
	int m_peer_limit;
	int m_peer_port;
	int m_seeding_ratio;
	int m_torrent_limit;
	int m_torrent_upload_slots_max;
	int m_torrent_upload_slots_min;
	int m_upload_rate;
	int m_upload_slots;
	std::string m_admin_user;
	std::string m_admin_pass;
	std::string m_completes_dir;
	std::string m_incompletes_dir;
	std::string m_local_app_data_dir;
	std::string m_peer_id_prefix;
	std::string m_public_ipa;
	std::string m_torrents_dir;
	std::string m_user_agent;
private:
	void fill_maps(const Cconfig*);
};

std::ostream& operator<<(std::ostream&, const Cconfig&);
