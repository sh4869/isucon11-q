
.PHONY: link
link:
	sudo cp -f /home/isucon/webapp/etc/mysql/mariadb.conf.d/50-server.cnf /etc/mysql/mariadb.conf.d/50-server.cnf
	sudo cp -f /home/isucon/webapp/etc/nginx/sites-enabled/isucondition.conf /etc/nginx/sites-enabled/isucondition.conf
	sudo cp -f /home/isucon/webapp/etc/nginx/nginx.conf /etc/nginx/nginx.conf
	sudo systemctl restart nginx
	sudo systemctl restart mariadb.service