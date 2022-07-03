DATE=$(shell date +%Y%m_%d_%H%M)

all: alp-analyze slowquery-analyze

rotate: 
	@echo "Rotating logs"
	sudo mv /var/log/nginx/access.log /var/log/nginx/access.log.$(DATE)  | :
	sudo mv /var/log/mysql/mysql-slow.log /var/log/mysql/mysql-slow.log.$(DATE)  | :
	sudo touch /var/log/nginx/access.log
	sudo chmod 666 /var/log/nginx/access.log
	sudo touch /var/log/mysql/mysql-slow.log
	sudo chmod 777 /var/log/mysql/mysql-slow.log
	make -C etc link
	make -C go/

alp-analyze:
	sudo cat /var/log/nginx/access.log | grep -v "\["  | alp json -m "/api/isu/.*/icon, /api/isu/.*/graph,/api/isu/.*,/api/condition/.*,/isu/.*/graph,/isu/.*/condition,/isu/.*,/assets/.*" --sort=sum -r | sudo tee log/nginx/digest.log.$(DATE)

slowquery-analyze:
	sudo pt-query-digest /var/log/mysql/mysql-slow.log | tee log/mysql/digest.log.$(DATE)
	sudo mysqldumpslow -s t /var/log/mysql/mysql-slow.log | tee log/mysql/digest.log.mysqldumpslow.$(DATE)