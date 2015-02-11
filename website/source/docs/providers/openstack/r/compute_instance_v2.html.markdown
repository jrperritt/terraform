---
layout: "openstack"
page_title: "OpenStack: openstack_compute_instance_v2"
sidebar_current: "docs-openstack-resource-compute-instance-v2"
description: |-
  Manages a V2 VM instance resource within OpenStack.
---

# openstack\_compute\_instance_v2

Manages a V2 VM instance resource within OpenStack.

## Example Usage

```
resource "openstack_compute_instance_v2" "test-server" {
  name = "tf-test"
  image_id = "ad091b52-742f-469e-8f3c-fd81cadf0743"
  flavor_ref = "3"
  metadata {
    this = "that"
  }
  key_pair = "my_key_pair_name"
  security_groups = ["test-group-1"]
}
```

## Argument Reference

The following arguments are supported:

* `region` - (Required) The region in which to create the server instance. If
    omitted, the `OS_REGION_NAME` environment variable is used. Changing this
    creates a new server.

* `name` - (Required) A unique name for the resource.

* `image_id` - (Required) The image ID of the desired image for the server.
    Changing this creates a new server. Note that `image_id` and `image_name`
    are mutually exclusive.

* `image_name` - (Required) The image name for the server. Changing this
   creates a new server. Note that `image_id` and `image_name` are mutually
   exclusive.

* `flavor_ref` - (Required) The flavor reference (ID) for the desired flavor
    for the server. Changing this resizes the existing server.

* `security_groups` - (Optional) An array of one or more security group names
    to associate with the server. Changing this results in adding/removing
    security groups from the existing server.

* `availability_zone` - (Optional) The availability zone in which to create
    the server. Changing this creates a new server.

* `network` - (Optional) An array of one or more networks to attach to the
    instance. The network object structure is documented below. Changing this
    creates a new server.

* `metadata` - (Optional) Metadata key/value pairs to make available from
    within the instance. Changing this updates the existing server metadata.

* `admin_pass` - (Optional) The administrative password to assign to the server.
    Changing this changes the root password on the existing server.

* `key_pair` - (Optional) The name of a key pair to put on the server. The key
    pair must already be created and associated with the tenant's account.
    Changing this creates a new server.

* `block_device` - (Optional) The object for booting by volume. The block_device
    object structure is documented below. Changing this creates a new server.

The `network` block supports:

* `uuid` - (Required unless `port` is provided) The network UUID to attach to
    the server.

* `port` - (Required unless `uuid` is provided) The port UUID of a network to
    attach to the server.

* `fixed_ip` - (Optional) Specifies a fixed IP address to be used on this
    network.

The `block_device` block supports:

* `uuid` - (Required) The UUID of the image, volume, or snapshot.

* `source_type` - (Required) The source type of the device. Must be one of
    "image", "volume", or "snapshot".

* `volume_size` - (Optional) The size of the volume to create (in gigabytes).

* `boot_index` - (Optional) The boot index of the volume. It defaults to 0.

* `destination_type` - (Optional) The type that gets created. Possible values
    are "volume" and "local".

## Attributes Reference

The following attributes are exported:

* `region` - See Argument Reference above.
* `name` - See Argument Reference above.
* `access_ip_v4` - See Argument Reference above.
* `access_ip_v6` - See Argument Reference above.
* `metadata` - See Argument Reference above.
* `security_groups` - See Argument Reference above.
* `flavor_ref` - See Argument Reference above.
