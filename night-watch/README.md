### Night Watch ansible

1. copy **inventory.yml.example** to inventory.yml, Replace REQUIRED_VARIABLES:

    REMOTE SSH  
    - YOUR_MACHINE_IP
    - YOUR_ANSIBLE_USER
    - YOUR_ANSIBLE_SSH_PASS | YOUR_SSH_KEY_FILE
    
    INPUT
    - YOUR_LOG_PATH
    - YOUR_TABLE_NAME
    
    OUTPUT INFLUXDB
    - YOUR_INFLUXDB_URL
    - YOUR_INFLUXDB_USERNAME
    - YOUR_INFLUXDB_PASSWORD
    
    OUTPUT PUSHGATEWAY
    - YOUR_PUSHGHATEWAY_URL

2. run connect test

    ``` 
    ansible -i inventory.yml all -m shell -a 'whoami'
    ```

3. run ansible playbook

   ```
   cd /path/to/night-watch-ansible
   ansible-playbook -i inventory.yml install.yml
   ```


#### Check Machine

1. copy **inventory.yml.example** to inventory.yml and set dashbase_proxy
like
```yaml
all:
  children:
    nightwatch:
      hosts:
        1.2.3.4:
          ansible_ssh_private_key_file: /Your/Key
      vars:
        dashbase_proxy: http://{YOUR_PROXY_URL}
```

2. run ansible playbook

   ```
   cd /path/to/night-watch-ansible
   ansible-playbook -i inventory.yml check.yml
   ```


