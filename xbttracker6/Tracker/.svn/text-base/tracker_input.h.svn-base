#pragma once

#include <string>

// TorrentPier begin
#include <socket.h>
// TorrentPier end

/**************************
ipv6的地址是128bit，v4的地址是32bit
使用每8bit一个byte按序储存的方式，ipv6需要16个byte，v4需要4个byte
如果使用符合习惯字符方式，ipv6：[ABCD:ABCD:ABCD:ABCD:ABCD:ABCD:ABCD:ABCD]，需要32个byte
XBT Tracker中ipv6统统是二进制串
返回给客户端时，整合了端口号，一个peer是18个byte
**************************/

//tracker处理url参数类
//参考BT协议：http://zh.wikipedia.org/wiki/BitTorrent%E5%8D%8F%E8%AE%AE%E8%A7%84%E8%8C%83
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
		e_none,                            //空（未指定）
		e_completed,
		e_started,
		e_stopped,
	};

	typedef std::vector<std::string> t_info_hashes; //hash列表

	t_event m_event;                        //事件
	std::string m_info_hash;                //torrent的hash值
	t_info_hashes m_info_hashes;            //多个hash值
	int m_ipa;                              //ipv4
	std::string m_peer_id;                  //peer_id
	long long m_downloaded;                 //已下载
	long long m_left;                       //剩余
	int m_port;                             //端口
	long long m_uploaded;                   //已上传
	int m_num_want;                         //希望从tracker接受到peer的数量

	// TorrentPier begin
	/*屏蔽开始
	std::string m_passkey;                  //url中的passkey，非PT时无需此玩意，长度一般为128位二进制数，16个bytes
	屏蔽结束*/
	bool m_ipv6set;                         //newpara
	char m_ipv6bin[16];                     //ipv6地址
	int m_family;                           //newpara
	// TorrentPier end
};
