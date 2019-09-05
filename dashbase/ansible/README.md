# Ansible Playbooks to deploy filebeat and telegraf

####### TO CONFIGURE DASHBASE AGNET ######

     0) update value of "pushgateway_url" in deploy.yml with correct value

     1) update value of "proxy_url" in deploy_filebeat.yml with correct host:port(port is default to `9200`).

     2) create app specific "app_name_nw.yml" file and place it under roles/telegraf/templates/configs/<app_name_nw.yml>

       multiple paths can be specified in the same app_name_nw.yml file
       Example with two paths:

       >cat roles/telegraf/templates/configs/syslog_nw.yml

        - paths: ["/var/log/syslog"]        # path to the logs, can be glob pattern
          java_format: "yyyy-MM-dd HH:mm:ss"                  # format of the date of log entries - java_format
          zone: Local                                         # time zone, if Local, then machine time zone will be detected automatically
          exclude_files: ['_']                                # pattern to use to exclude files (optional parameter)

###### TO DEPLOY DASHBASE AGENT ######

     1) populate the inventory file
        Example:

        >cat inventory_syslog

        [syslog_hosts]
        192.168.131.98
        192.84.16.128

        ; See further configurations in https://docs.ansible.com/ansible/latest/user_guide/intro_inventory.html
        ; [freeswitch:vars]
        ; ansible_user=admin

     3) run the playbook

       >ansible-playbook -i inventory_syslog deploy_deploy.yml -e "index=applogs app_name=syslog"

       Playbook takes these extra variables with -e (or will prompt for):

       index            - name of dashbase index to send logs to
       app_name         - name(s) of the applications (multiple app names can be given as a comma separated values)
