#include "stdafx.h"
#include "transaction.h"

#include <sha1.h>
#include "server.h"

Ctransaction::Ctransaction(const Csocket& s) : 
	m_s(s)
{
}

long long Ctransaction::connection_id() const
{
	const int cb_s = 12;
	char s[cb_s];
	write_int(8, s, srv_secret());
	write_int(4, s + 8, m_a.sin_addr.s_addr);
	char d[20];
	Csha1(data_ref(s, cb_s)).read(d);
	return read_int(8, d);
}

void Ctransaction::recv()
{
	const int cb_b = 2 << 10;
	char b[cb_b];
	for (int i = 0; i < 10000; i++)
	{
		socklen_t cb_a = sizeof(sockaddr_in);
		int r = m_s.recvfrom(mutable_data_ref(b, cb_b), reinterpret_cast<sockaddr*>(&m_a), &cb_a);
		if (r == SOCKET_ERROR)
		{
			if (WSAGetLastError() != WSAEWOULDBLOCK)
				std::cerr << "recv failed: " << Csocket::error2a(WSAGetLastError()) << std::endl;
			return;
		}
		srv_stats().received_udp++;
		if (r < uti_size)
			return;
		switch (read_int(4, b + uti_action, b + r))
		{
		case uta_connect:
			if (r >= utic_size)
				send_connect(data_ref(b, r));
			break;
		case uta_announce:
			if (r >= utia_size)
				send_announce(data_ref(b, r));
			break;
		case uta_scrape:
			if (r >= utis_size)
				send_scrape(data_ref(b, r));
			break;
		}
	}
}

void Ctransaction::send_connect(data_ref r)
{
	if (read_int(8, &r[uti_connection_id], r.end()) != 0x41727101980ll)
		return;
	const int cb_d = 2 << 10;
	char d[cb_d];
	write_int(4, d + uto_action, uta_connect);
	write_int(4, d + uto_transaction_id, read_int(4, &r[uti_transaction_id], r.end()));
	write_int(8, d + utoc_connection_id, connection_id());
	send(data_ref(d, utoc_size));
}

void Ctransaction::send_announce(data_ref r)
{
	if (read_int(8, &r[uti_connection_id], r.end()) != connection_id())
		return;
	if (!srv_config().m_anonymous_announce)
	{
		send_error(r, "access denied");
		return;
	}
	Ctracker_input ti;
	ti.m_downloaded = read_int(8, &r[utia_downloaded], r.end());
	ti.m_event = static_cast<Ctracker_input::t_event>(read_int(4, &r[utia_event], r.end()));
	ti.m_info_hash.assign(reinterpret_cast<const char*>(&r[utia_info_hash]), 20);
	ti.m_ipa = read_int(4, &r[utia_ipa], r.end()) && is_private_ipa(m_a.sin_addr.s_addr)
		? htonl(read_int(4, &r[utia_ipa], r.end()))
		: m_a.sin_addr.s_addr;
	ti.m_left = read_int(8, &r[utia_left], r.end());
	memcpy(ti.m_peer_id.data(), &r[utia_peer_id], 20);
	ti.m_port = htons(read_int(2, &r[utia_port], r.end()));
	ti.m_uploaded = read_int(8, &r[utia_uploaded], r.end());
	std::string error = srv_insert_peer(ti, true, NULL);
	if (!error.empty())
	{
		send_error(r, error);
		return;
	}
	auto torrent = find_torrent(ti.m_info_hash);
	if (!torrent)
		return;
	char d[2 << 10];
	write_int(4, d + uto_action, uta_announce);
	write_int(4, d + uto_transaction_id, read_int(4, &r[uti_transaction_id], r.end()));
	write_int(4, d + utoa_interval, srv_config().m_announce_interval);
	write_int(4, d + utoa_leechers, torrent->leechers);
	write_int(4, d + utoa_seeders, torrent->seeders);
	mutable_str_ref peers(d + utoa_size, 300);
	torrent->select_peers(peers, ti);
	send(data_ref(d, peers.begin()));
}

void Ctransaction::send_scrape(data_ref r)
{
	if (read_int(8, &r[uti_connection_id], r.end()) != connection_id())
		return;
	if (!srv_config().m_anonymous_scrape)
	{
		send_error(r, "access denied");
		return;
	}
	const int cb_d = 2 << 10;
	char d[cb_d];
	write_int(4, d + uto_action, uta_scrape);
	write_int(4, d + uto_transaction_id, read_int(4, &r[uti_transaction_id], r.end()));
	char* w = d + utos_size;
	for (r.advance_begin(utis_size); r.size() >= 20 && w + 12 <= d + cb_d; r.advance_begin(20))
	{
		if (auto t = find_torrent(r.substr(0, 20).s()))
		{
			w = write_int(4, w, t->seeders);
			w = write_int(4, w, t->completed);
			w = write_int(4, w, t->leechers);
		}
		else
		{
			w = write_int(4, w, 0);
			w = write_int(4, w, 0);
			w = write_int(4, w, 0);
		}
	}
	srv_stats().scraped_udp++;
	send(data_ref(d, w));
}

void Ctransaction::send_error(data_ref r, const std::string& msg)
{
	char d[2 << 10];
	write_int(4, d + uto_action, uta_error);
	write_int(4, d + uto_transaction_id, read_int(4, &r[uti_transaction_id], r.end()));
	memcpy(d + utoe_size, msg);
	send(data_ref(d, utoe_size + msg.size()));
}

void Ctransaction::send(data_ref b)
{
	if (m_s.sendto(b, reinterpret_cast<const sockaddr*>(&m_a), sizeof(sockaddr_in)) != b.size())
		std::cerr << "send failed: " << Csocket::error2a(WSAGetLastError()) << std::endl;
	srv_stats().sent_udp++;
}
