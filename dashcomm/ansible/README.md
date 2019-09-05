# Ansible Playbooks to deploy Dashcomm agent for freeswitch (DAFS)

##### TO CONFIGURE DASHCOMM AGENT #####

     0) update value of "pushgateway_url" in deploy.yml with correct value

     1) update value of "table_url" in deploy_filebeat.yml with correct host:port(port is default to `9200`).

##### TO DEPLOY DASHCOMM AGENT #####

     1) populate the inventory file
        Example:

        >cat inventory

        [freeswitch]
        192.168.131.98
        192.84.16.128

     2) run the playbook

       >ansible-playbook -i inventory deploy.yml -e "index=freeswitch app_name=freeswitch"

       Playbook takes these extra variables with -e (or will prompt for):

       index            - name of dashbase index to send logs to
       app_name         - name(s) of the applications (multiple app names can be given as a comma separated values)