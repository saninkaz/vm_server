
# SSL Admin Tasks

This doc consists of all the tasks i have done, and the documentation of each task.

Optional tasks at the end.

Future implementations that can be done:

1) Jenkins automation for my personal portfolio website.
2) Prevent the server from DDOS attacks
3) Host my main project in this VM


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
		    	#!/bin/bash
	
			BACKUP_DIR="/home/examadmin/backups"
			DATE=$(date +%Y%m%d)
			LOG_FILE="$BACKUP_DIR/backup_$DATE.log"
			
			check_user() {
			    if ! id -u "examadmin" &>/dev/null; then
			        echo "This script is only accessible to examadmin!" | tee -a "$LOG_FILE"
			        exit 1
			    fi
			}
			
			
			backup_users() {
			    mkdir -p "$BACKUP_DIR"
			    echo "Backup started at $(date)" >> "$LOG_FILE"
			
			    for dir in /home/exam_*; do
			        if [ -d "$dir" ]; then
			            user=$(basename "$dir")
			            tar -czf "$BACKUP_DIR/${user}_$DATE.tar.gz" "$dir" 2>>"$LOG_FILE"
			            echo "Backed up $user directory" >> "$LOG_FILE"
			        fi
			    done
			
			    echo "Backup completed at $(date)" >> "$LOG_FILE"
			}
			
			check_user
			backup_users

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
            - nano blest.sslnitc.site
                server {
	                    listen 80;
	                    server_name blest.sslnitc.site;
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
            - configure ssl certificate using certbot (for nginx)
            - sudo ln -s /etc/nginx/sites-available/sanin_ssl /etc/nginx/sites-enabled/
            - cd /etc/nginx/sites-enabled
            - sudo rm default
            - sudo systemctl reload nginx

### 2) Content Security Policy (CSP):

            - sudo nano /etc/nginx/nginx.conf

            Add lines -
                add_header X-XSS-Protection "1; mode=block";
                add_header Content-Security-Policy "default-src 'self'; script-src 'self';";

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
            - docker run -itd --name ansible_control --network ansible-net ubuntu /bin/bash
            - docker run -itd --name ansible_target_1 --cap-add=NET_ADMIN --network ansible-net ubuntu /bin/bash
            - docker run -itd --name ansible_target_2 --cap-add=NET_ADMIN --network ansible-net ubuntu /bin/bash

            - (Note that NET_ADMIN capability is needed for modifying ufw firewall rules in target containers or it will cause permission issue, i had to stop the container and commit the changes of the containers to a new image and then restarted the container with NET_ADMIN capability)

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

### 2) Lab Configuration Management:

                - vi comp_playbook.yml

                    ---
                    
                    - name: Comprehensive Playbook
                    become: true
                    hosts: targets
                    vars_files: 
                        - vars/comp_vars.yml


                    tasks: 
                    - name: Install Packages
                        apt:
                        name: "{{ item }}"
                        state: present #ensures the packages are installed
                        #update_cache: yes #to update package index before installing
                        loop: "{{ packages }}"

                    - name: Bash aliases
                        lineinfile:
                        path: /etc/bash.bashrc
                        line: "{{ item }}"
                        create: yes
                        loop:
                        - 'alias ..="cd .."'
                        - 'alias tx="tmux"'

                    - name: Vim settings
                        lineinfile:
                        path: /etc/vim/vimrc
                        line: "{{ item }}"
                        create: yes
                        loop:
                        - 'set number'
                        - 'set wrap'
                        - 'syntax on'


                    - name: Install ufw
                        apt:
                        name: ufw
                        state: present

                    - name: Configuring ufw
                        ufw:
                        direction: incoming
                        policy: deny

                    - name: Configuring ufw2
                        ufw: 
                        direction: outgoing
                        policy: allow

                    - name: Allow SSH
                        ufw:
                        rule: allow
                        name: OpenSSH

                    - name: Allow http and https
                        ufw:
                        rule: allow
                        port: "{{ item }}"
                        proto: tcp
                        loop:
                        - '80'
                        - '443'

                    - name: Enable ufw
                        ufw:
                        state: enabled


                    ## SSH Configuration

                    - name: Disable password authentication
                        lineinfile:
                        path: /etc/ssh/sshd_config
                        state: present
                        regexp: '^PasswordAuthentication'
                        line: 'PasswordAuthentication no'

                    - name: SSH Restart
                        shell: service ssh restart
                        async: 10
                        poll: 0

                - Save and exit

### 2) Ansible Roles for Lab Management:

                - cd /etc/ansible
                - mkdir roles
                - cd roles
                - ansible-galaxy role init lab-base
                - ansible-galaxy role init student-workstation
                - cd lab-base
                - vi tasks/main.yml

                      - name: Install updates
                        apt:
                            upgrade: dist
                            update_cache: yes

                      - name: Configure timezone
                        timezone:
                            name: "{{ timezone }}"

                      - name: Set Hostname
                        hostname:
                            name: "{{ hostname }}"

                      - name: Intall Netdata (monitoring tool)
                        apt:
                            name: netdata
                            state: present
                
                - Save and exit (define the variables in vars/main.yml)

                - cd /etc/ansible/roles/student-workstation
                - vi taks/main.yml (referred vs code installion from https://github.com/gantsign/ansible-role-visual-studio-code/tree/master)


                - name: Create student account
                user:
                    name: "{{ student_user }}"
                    shell: /bin/bash
                    state: present
                    create_home: yes #Creates home directory for the student user

                - name: Install development tools
                  apt:
                    name: "{{ development_packages }}"
                    state: present

                - name: Install dependencies (apt)
                  apt:
                    name:
                    - ca-certificates
                    - apt-transport-https
                    state: present

                - name: Create APT keyrings dir
                  become: true
                  file:
                    path: '/etc/apt/keyrings'
                    state: directory
                    mode: 'u=rwx,go=rx'

                - name: Install key (apt)
                  become: true
                  get_url:
                    url: '{{ visual_studio_code_mirror }}/keys/microsoft.asc'
                    dest: '/etc/apt/keyrings/'
                    mode: 'u=rw,go=r'
                    force: true

                - name: Add VSCode repository
                  apt_repository:
                    repo: "deb [arch=amd64 signed-by=/etc/apt/keyrings/microsoft.asc] {{ visual_studio_code_mirror }}/repos/code stable main"
                    state: present
                    filename: vscode

                - name: Update apt cache after adding VSCode repo
                  apt:
                    update_cache: yes
                when: ansible_facts['os_family'] == "Debian"

                - name: Install VSCode
                  apt:
                    name: code
                    state: present
                    update_cache: yes


                -- Save and exit

# OPTIONAL TASKS

## Task 1): Load Balancer Setup

            - Download the app or set up the app(python code)
            - (Make sure u installed python3 and set up)
            - python3 app.py 8080 &
            - python3 app.py 8081 &
            - python3 app.py 8082 &
            - python3 app.py 8083 & (& makes the app run in backgound)

            - vi /etc/nginx/sites-available/sanin_ssl

                # add new upstream backend server outside server block

                upstream backend {
                server 127.0.0.1:8080;
                server 127.0.0.1:8081;
                server 127.0.0.1:8082;
                server 127.0.0.1:8083;
                }

                # add new location path in server block

                location /loadBalancer/ {
                    proxy_pass http://backend;
                }
            - Save and exit
            - sudo nginx -t
            - sudo systemctl reload nginx
            - (Load balancer is running successfully)


## Task 2): Advanced Docker Containerization

### 1. Nextcloud Containerization Project:

            - sudo mkdir -p /nextcloud
            - cd /nextcloud
            - sudo mkdir proxy
            - sudo vi proxy/Dockerfile

                    FROM nginxproxy/nginx-proxy:alpine

                    Save and exit
            
            - sudo wget https://git.pimylifeup.com/compose/nextcloud/.env (reference from a youtube video)
            - sudo nano .env

                    MYSQL_PASSWORD=<set-your-password>
                    STORAGE_LOCATION=/nextcloud/data
                    DOMAIN_NAME=blest.sslnitc.site (your domain name)
                    LETS_ENCRYPT_EMAIL=<your-email>

            - sudo wget https://git.pimylifeup.com/compose/nextcloud/signed/compose.yaml

            - Go through the file and understand the workflow of the services

            - docker compose up -d

            - Your Nextcloud server is successfully running on port 80

            (Make sure to disable the portfolio website nginx before running this conatiner , this makes sure nextcloud server can run on the domain port 80 successfully)
            





