#pragma once

#include <string>

// TorrentPier begin
#include <socket.h>
// TorrentPier end

/**************************
ipv6�ĵ�ַ��128bit��v4�ĵ�ַ��32bit
ʹ��ÿ8bitһ��byte���򴢴�ķ�ʽ��ipv6��Ҫ16��byte��v4��Ҫ4��byte
���ʹ�÷���ϰ���ַ���ʽ��ipv6��[ABCD:ABCD:ABCD:ABCD:ABCD:ABCD:ABCD:ABCD]����Ҫ32��byte
XBT Tracker��ipv6ͳͳ�Ƕ����ƴ�
���ظ��ͻ���ʱ�������˶˿ںţ�һ��peer��18��byte
**************************/

//tracker����url������
//�ο�BTЭ�飺http://zh.wikipedia.org/wiki/BitTorrent%E5%8D%8F%E8%AE%AE%E8%A7%84%E8%8C%83
class Ctracker_input
{
public:
	void set(const std::string& name, const std::string& value);
	bool valid() const;

	// TorrentPier begin
	Ctracker_input(int family = AF_INET);  //newfun
	// TorrentPier end

	enum t_event
	{
		e_none,                            //�գ�δָ����
		e_completed,
		e_started,
		e_stopped,
	};

	typedef std::vector<std::string> t_info_hashes; //hash�б�

	t_event m_event;                        //�¼�
	std::string m_info_hash;                //torrent��hashֵ
	t_info_hashes m_info_hashes;            //���hashֵ
	int m_ipa;                              //ipv4
	std::string m_peer_id;                  //peer_id
	long long m_downloaded;                 //������
	long long m_left;                       //ʣ��
	int m_port;                             //�˿�
	long long m_uploaded;                   //���ϴ�
	int m_num_want;                         //ϣ����tracker���ܵ�peer������

	// TorrentPier begin
	/*���ο�ʼ
	std::string m_passkey;                  //url�е�passkey����PTʱ��������⣬����һ��Ϊ128λ����������16��bytes
	���ν���*/
	bool m_ipv6set;                         //newpara
	char m_ipv6bin[16];                     //ipv6��ַ
	int m_family;                           //newpara
	// TorrentPier end
};
