from collections import namedtuple


# TODO(alecmerdler): Are these all the fields we want...?
Container = namedtuple("Container", ["name", "pod_name", "namespace", "cluster_id", "image", "image_id", "state"])


def live_tags(client, k8s_clusters=[], app_hostname=""):
    """
    Searches all linked Kubernetes clusters and finds all the image tags
    that are being used by running pods.
    """

    for cluster in k8s_clusters:
        res = client.get(cluster["endpoint"] + "/api/v1/pods")
        pods_list = res.json()

        # TODO(alecmerdler): Make these `reduce` functions
        containers = []
        for pod in pods_list["items"]:
            for container_status in pod["status"]["containerStatuses"]:
                containers.append(Container(
                    name=container_status["name"], 
                    pod_name=pod["metadata"]["name"], 
                    namespace=pod["metadata"]["namespace"],
                    cluster_id=cluster["name"],
                    image=container_status["image"],
                    image_id=container_status["imageID"],
                    state=container_status["state"],
                ))

        from_this_registry = filter(
            lambda container: container.image.startswith(app_hostname), containers
        )

        return from_this_registry
