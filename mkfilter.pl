#!/usr/bin/perl
# KRフィルタ
use Socket;

# 拒否する国コード
@country = ('KR', 'CN');
# IPアドレス一覧取得URL
$url = "http://ftp.apnic.net/stats/apnic/delegated-apnic-latest";

# iptables 初期化
system("/etc/init.d/iptables restart");

# 挿入位置を取得 (接続済みパケットは許可する設定の次に挿入)
if(open(IN, "iptables -L INPUT --line-number|")){
	while(<IN>){
		if(/^(\d+).*RELATED,ESTABLISHED.*/){
			$rule = $1 + 1;
			last;
		}
	}
	close(IN);
}

# 初期処理
foreach $i (@country){
	$country{$i} = 1;
}

if(open(IN, "wget -q -O - $url|")){
	while(<IN>){
		if(/^apnic\|(..)\|ipv4\|(\d+.\d+.\d+.\d)\|(\d+)/){
			if($country{$1}){
				$table{inet_aton($2)} = $3;
			}
		}
	}
	close(IN);

	# IPアドレス一覧を CIDR 型式に変換
	foreach $net (sort keys %table){
		$addr = unpack('N', $net);
		$num = $table{$net};
		while($num == $num[0] && ($addr ^ $addr[0]) == $num){
			shift @addr;
			shift @num;
			$addr &= ~$num;
			$num <<= 1;
		}
		unshift(@addr, $addr);
		unshift(@num, $num);
	}

	# iptables 実行
	while (@addr){
		for($num = pop(@num), $mask = 32; $num > 1; $num >>= 1, $mask--){}
		$filt = inet_ntoa(pack('N', pop(@addr))) . "/$mask";
		system("iptables -I INPUT $rule -s $filt -j DROP");
		$rule++;
	}
}

0;
