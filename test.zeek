global srcIPToAgent : table[addr] of set[string] = table();

event http_header (c: connection, is_orig: bool, name: string, value: string){
	if(c$http?$user_agent){
		local src_ip=c$id$orig_h;
		local user_agent=to_lower(c$http$user_agent);
		if(src_ip in srcIPToAgent){
			add (srcIPToAgent[src_ip])[user_agent];
		}else{
			srcIPToAgent[src_ip]=set(user_agent);
		}
	}
}

event zeek_done() {
	for (src_ip in srcIPToAgent) {
	    if (|srcIPToAgent[src_ip]| >= 3) {
	        print fmt("%s is a proxy", src_ip);
	    }
	}
}