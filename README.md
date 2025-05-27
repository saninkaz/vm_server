# SSL Admin Tasks

This doc consists of all the tasks i have done, and the step by step process and documentation of each task.

## Task 1 (Initial Setup)

### 1) Create an Ubuntu VM in Azure: 
        configured an azure server with 1gb ram 1vcpu (version Ubuntu 22.04)

### 2) System Updates and Security: 
        - sudo apt update
        - sudo apt upgrade

        Unattended upgrades -

        - sudo apt install unattended-upgrades -y
        - sudo vim /etc/apt/apt.conf.d/50unattended-upgrades
            make sure these lines are uncommented
                "${distro_id}:${distro_codename}";
                "${distro_id}:${distro_codename}-security";


        - sudo vim /etc/apt/apt.conf.d/20auto-upgrades
            make sure lines are
                APT::Periodic::Update-Package-Lists "1";
                APT::Periodic::Unattended-Upgrade "1";
                APT::Periodic::Download-Upgradeable-Packages "1"; 

        - sudo systemctl restart unattended-upgrades.service (restart service)
        

## Task 2 (Enhanced SSH Security)

### 1) SSH Configuration:
            
            - sudo nano /etc/ssh/sshd_config

                    PermitRootLogin no
                    PasswordAuthentication no
                    PubkeyAuthentication yes

            - sudo systemctl restart sshd

            Setting up fail2ban -

                    - sudo apt update
                    - sudo apt install fail2ban
                    - cd /etc/fail2ban
                    - sudo cp jail.conf jail.local
                    - sudo nano jail.local

                    Under the [sshd]

                    Add line    
                            
                            enabled = true

                    - sudo systemctl enable fail2ban
                    - sudo systemctl start fail2ban
                    - sudo systemctl status fail2ban (check if fail2ban is running)


## Task 3 (Firewall and Network Security)


### 1) Firewall Configuration:

            - sudo systemctl status ufw (check whether ufw is installed)
            - (Open port 2222 in azure port rules and also change the default port of ssh to 2222 using sshd_config file)

             Make sure the subsequent commands are done fully before closing the   ssh connection (or else you will be locked out from the server)

            - sudo ufw default deny incoming
            - sudo ufw default allow outgoing
            - sudo ufw allow 2222
            - sudo ufw allow http
            - sudo ufw allow https
            - sudo ufw show added (outputs all the current rules added)
            - sudo ufw enable
            
            (Your Firewall is activated)

            Logging ufw -

                - sudo ufw logging on

### 2) Intrusion Detection System (IDS):

            Configuring Snort -

            - sudo apt-get install snort -y
            - sudo nano /etc/snort/snort.conf

                set the line 
                    ipvar HOME_NET any to ipvar HOME_NET 10.0.0.0/24 (your private ip address of vm)

            - sudo snort -T -i eth0 -c /etc/snort/snort.conf (if snort is configured this command will run successfully without errors)

            Writing Snort Rules -

                - sudo nano /etc/snort/rules/local.rules 
                Add lines (basic rules)

                    alert icmp any any -> $HOME_NET any (msg:”ICMP Detection Rule”; sid:100001;)
                    alert tcp any any -> $HOME_NET 2222 (msg: “SSH Connection Attempts”; sid:100002; )
            
                You can view realtime snort alerts with this command
                    - sudo snort -q -l /var/log/snort -i eth0 -A console -c /etc/snort/snort.conf

## Task 4 (User and Permission Management)

### 1) User Setup:

            - sudo adduser exam_1
            - sudo adduser exam_2
            - sudo adduser exam_3
            - sudo adduser examadmin
            - sudo adduser examaudit
            - sudo usermod -aG sudo examadmin

            Give permissions- (log in as sudo user)

            - sudo chmod 700 exam_1
            - sudo chmod 700 exam_2
            - sudo chmod 700 exam_3

            (setting permissions for examaudit)

            - sudo find /home/exam_1 /home/exam_2 /home/exam_3 -type d -exec setfacl -m u:examaudit:rx {} \;
            - sudo find /home/exam_1 /home/exam_2 /home/exam_3 -type f -exec setfacl -m u:examaudit:r {} \;

            (setting permissions for examadmin)

            - sudo find /home/exam_1 /home/exam_2 /home/exam_3 /home/examaudit -exec setfacl -m u:examadmin:rwx {} \;

### 2) Home Directory Security:

            - Already set up the permissions

            Setting up quotas- (log in a sudo)

                - apt install quota
                - apt install linux-modules-extra-azure
                
                - (reboot server)

                - nano /etc/fstab

                    Replace defaults with usrqouta,grpquota on root disk (mostly first line and directory location /)
                - mount -o remount /
                - cat /proc/mounts | grep ' / ' (verify whether the new options are added)
                - quotacheck -ugm /
                - modprobe quota_v1 -S 6.8.0-1028-azure
                - modprobe quota_v2 -S 6.8.0-1028-azure
                - quotaon -v /
                - edquota -u exam_i 
                 THis will open a file like this 

                        Disk quotas for user exam_1 (uid 1001):
                        Filesystem                   blocks       soft       hard     inodes     soft     hard
                        /dev/root                        28          0          0          9        0        0

                ( edit quotas for each user by setting soft and hard limits)

### 3) Backup Script: 

            - su - examdmin
            - nano backup_exam.sh
            - chmod 700 backup_exam.sh
            - ./backup_exam.sh

            For daily executions:

            - crontab -e

                Add line

                    0 3 * * * /home/examadmin/backup_exam.sh (This will execute the script daily at 3AM)


## Task 5 (Web Server Deployment and Secure Configuration )

### 1) Reverse Proxy Configuration: 

            - apt install nginx (install nginx if not)
            - adduser user_np (non privileged user) (make sure ur logged in as sudo user to perform this task)
            - su - user_np
            - wget -O app1 https://do.edvinbasil.com/ssl/app
            - wget -O app1.sha256.sig https://do.edvinbasil.com/ssl/app.sha256.sig

            Verify the signature -

                    - sha256sum app1
                    - cat app1.sha256.sum 
                    - compare both the outputs and verify if its same.

            - chmod +x app1
            - tmux new -s app1 ( creates a new tmux session with name app1)
                - ./app1
                CTRL B + D (Detach)
            
            - git clone https://gitlab.com/tellmeY/issslopen.git (clone issslopen app)
            - Log in as sudo user
            - (Install Docker and setup)
            - usermod -aG docker user_np (add the non-privileged user to the docker group)
            - su - user_np
            - cd /issslopen

            - nano Dockerfile

                COPY --from=prerelease /usr/src/app/edit.html /usr/src/app/edit.html (add this under second # Copy public folder)

            - nano docker-compose.yaml 
                Comment or change image directory to 
                    image: issslopen:1.0 (starts from new version instead of pulling existing image)
                
            - rename .env.example to .env
            (This is used to edit the issslopen page for users with tokens,refer the issslopen readme)
 
            
            - docker build -t issslopen:1.0 .
            - docker compose up -d

            Now app1 and app2 is successfully running on port 8008 and 3000 respectively

            - Log in as sudo user
            - cd /etc/nginx/sites-available
            - nano sanin_ssl
                server {
	                    listen 80;
	                    server_name sanin_ssl.com;
	                    location /server1/ {
		                    proxy_pass http://localhost:8008/server1/;
	                    }       
	                    location /server2/ {
		                    proxy_pass http://localhost:8008/;
	                    }
	                    location /sslopen {
		                    proxy_pass http://localhost:3000/sslopen/;
	                    }   
                }
            - configure ssl certificate using certbot
            - sudo ln -s /etc/nginx/sites-available/sanin_ssl /etc/nginx/sites-enabled/
            - cd /etc/nginx/sites-enabled
            - sudo rm default
            - sudo systemctl reload nginx

### 2) Content Security Policy (CSP):

            - sudo nano /etc/nginx/nginx.conf

            Add lines -
                add_header X-XSS-Protection "1; mode=block";
                add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline';";

            under http block in nginx.conf file


## Task 6 (Database Security):

### 1) Database Setup:

            - Log in a sudo user
            - sudo apt update
            - sudo apt install mariadb-server
            - sudo mysql_secure_installation

                Enter current password for root (enter for none): (press enter)
                Switch to unix_socket authentication [Y/n] n
                Change the root password? [Y/n] n
                Remove anonymous users? [Y/n] Y
                Disallow root login remotely? [Y/n] Y (this disallows remote root login)
                Remove test database and access to it? [Y/n] Y
                Reload privilege tables now? [Y/n] Y


            - sudo systemctl status mariadb (check if it is correctly running)

            -  sudo mysql -u root (log in to mariadb shell)

                    - CREATE DATABASE secure_onboarding;
                    - show databases (confirm if it is created)
                    - CREATE USER 'user_mp'@'localhost' IDENTIFIED BY 'password';
                    - SELECT * FROM mysql.user; (check if user is created)
                    - GRANT INSERT, UPDATE, DELETE, SELECT, REFERENCES ON secure_onboarding.* TO 'user_mp'@'localhost'; (grant minimal privileges)
                    - FLUSH PRIVILEGES;
                    - SHOW GRANTS FOR 'user_mp'@'localhost'; (check if grants are successfully given)

            
### 2) Database Security:

            - Already disabled remote root login in previous step
            - cd ~
            - mkdir db_backup
            - sudo nano /etc/.my.cnf

                [client]
                user=user_mp  #Database user
                password=password #Database user password

                Save and exit

            - chmod 600 .my.cnf
            - sudo nano /etc/db_backup.sh

                #!/bin/bash
                mysqldump secure_onboarding > ~/db_backup/db_backup-$(date +\%F).sql

            - chmod +x db_backup.sh
            - crontab -e
                Add line

                0 2 * * * ~/db_backup/db_backup.sh 

                (This is for automatic backups)

## Task 7 (VPN Configuration):

### 2) VPN Setup:

            - Log in as sudo user
            - sudo apt install wireguard
            - wg genkey | sudo tee /etc/wireguard/private.key
            - sudo chmod go= /etc/wireguard/private.key
            - sudo cat /etc/wireguard/private.key | wg pubkey | sudo tee /etc/wireguard/public.key

            - (Note down the public and private keys)
            - sudo nano /etc/wireguard/wg0.conf

                [Interface]
                PrivateKey = <your_private_key>
                Address = 10.8.0.1/24
                ListenPort = 51820
                SaveConfig = true

                PostUp = ufw route allow in on wg0 out on eth0
                PostUp = iptables -t nat -I POSTROUTING -o eth0 -j MASQUERADE
                PostUp = ip6tables -t nat -I POSTROUTING -o eth0 -j MASQUERADE
                PreDown = ufw route delete allow in on wg0 out on eth0
                PreDown = iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
                PreDown = ip6tables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

            

            - sudo nano /etc/sysctl.conf

                Uncomment line -

                net.ipv4.ip_forward=1

                (Save and exit)

            - sudo sysctl -p (check if it outputs net.ipv4.ip_forward=1)
            - sudo ufw allow 51820/udp
            - (open new inbound port rule for 51820 in azure vm portal)
            - sudo ufw allow 53 (for dns requests)
            - sudo ufw status (check if every rule is added correctly)
            - sudo ufw enable
            - sudo systemctl enable wg-quick@wg0.service (for starting the wg server)
            - sudo systemctl start wg-quick@wg0.service
            - sudo systemctl status wg-quick@wg0.service ( check if wg server is successfully running)
            
            (For creating vpn credentials for two users)-
                 - Generate two pairs of public key and private key;
                 - add the public key to the server file using set peer
                 - configure on the client


## Task 8 (Docker Fundamentals and Personal Website Deployment):

### 1) Basic Docker Setup:

            - (Already set up docker using docker docs in Task 5)

            - sudo systemctl enable docker.service
            - sudo systemctl enable containerd.service (configure docker for system boot)
            - newgrp docker
            - docker run hello-world

### 2) Deploying a Portfolio Website via Docker and Nginx:

            - (made website using react)
            - (cloned using git clone from github)
            - nano Dockerfile

                FROM node:latest

                WORKDIR /app

                COPY package*.json ./

                RUN npm ci --legacy-peer-deps

                COPY . .

                RUN npm run build

                EXPOSE 3000

                CMD ["npm","start"]

            - nano .dockerignore

                node_modules
                Dockerfile
                .dockerignore
                .env

            - docker build -t portfolio:1.0 .
            - docker run -d -p 3001:3000 --mount type=volume,source=sanin,target=/app --restart always --cap-add=NET_ADMIN --cap-add=SYS_TIME portfolio:1.0

            (--restart flag makes sure the container starts automatically on boot)
            (--mount is used for mounting the website content for persistence)
            (--cap-add is used for adding linux capabilites)


            (Setting up nginx reverse proxy) - 

            - cd /etc/nginx/sites-available
            - nano sanin_ssl

                Add line
                location / {
                    proxy_pass http://localhost:3001/; 
                }

            - sudo nginx -t
            - sudo sytemctl restart nginx
            (Now the portfolio website will be accessible with VM's ip)

## Task 9 (Ansible Automation in Dockerized Lab Environment):

### 1) Ansible Setup and Basics:

            - docker create network ansible-net
            - docker run -itd --name ansible_control --network ansible_net ubuntu /bin/bash
            - docker run -itd --name ansible_target_1 --network ansible_net ubuntu /bin/bash
            - docker run -itd --name ansible_target_2 --network ansible_net ubuntu /bin/bash

            - docker attach ansible_control (gets inside the ansible_control container)

                - apt update
                - apt install python3 python3-pip ansible openssh-client vim iputils-ping -y
                - CTRL P + Q (for exiting)

            - docker attach ansible_target_1

                - passwd root (set password for root)
                - apt update
                - apt install openssh-server iputils-ping vim -y
                - vi /etc/ssh/sshd_config

                    Uncomment and change these lines -

                    PermitRootLogin yes
                    PasswordAuthentication yes

                - service ssh restart
                - CTRL P + Q

            (Do the same for ansible_target_2)

            - docker attach ansible_control

                - ssh-keygen -t rsa -b 2048 -f ~/.ssh/id_rsa -q 
                - ssh-copy-id -i ~/.ssh/id_rsa.pub root@172.19.0.3(ansible_target_1 ip)
                - ssh-copy-id -i ~/.ssh/id_rsa.pub root@172.19.0.4(ansible_target_2 ip)

                - mkdir -p /etc/ansible (sometimes ansible hsots file will not be created automatically)
                - cd /etc/ansible
                - touch hosts
                - chmod 644 hosts
                - vi hosts

                    Add lines

                    [targets]
                    <target_1_ip>
                    <target_2_ip>

                    Save and exit (:wq)

                - ansible-config init --disabled -t all > ansible.cfg (for creating default ansible configuration file)
                - mkdir playbooks
                - cd playbooks
                - vi basic_playbook.yml

                    ---
                    - name: basic_playbook
                      hosts: targets

                      tasks:
                      - name: Ping Target
                        ping:

                      - name: Check Disk Space
                        command: df -h

                      - name: Show system uptime
                        command: uptime

                - ansible-playbook basic_playbook.yml (runs the playbook)

                (For further tasks , i created a new user in the two containers and also installed ssh keys and copied them) 
                (this was done to check the working of the comprehensive playbook made)

                - vi comp_playbook.yml
