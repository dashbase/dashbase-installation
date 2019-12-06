from kubernetes import client, config

# Configs can be set in Configuration class directly or using helper utility
config.load_kube_config("/Users/June/.kube/config")
# config.incluster_config

v1 = client.CoreV1Api()


# print("Listing pods with their IPs:")
# ret = v1.list_pod_for_all_namespaces(watch=False)
# for i in ret.items:
#     print("%s\t%s\t%s" % (i.status.pod_ip, i.metadata.namespace, i.metadata.name))


def get_nodes():
    ret = v1.list_node(watch=False)
    return [node.metadata.name for node in ret.items]


def get_pods(node):
    selector = "spec.nodeName={},status.phase!=Failed,status.phase!=Succeeded".format(node)
    ret = v1.list_pod_for_all_namespaces(field_selector=selector)
    # //ret.items[0].spec.containers[0].resources.limits
    return [pod.metadata.name for pod in ret.items]


if __name__ == '__main__':
    # print("This script will try to get all nodes")
    nodes = get_nodes()
    print(nodes)
    print(get_pods(nodes[0]))
