package openstack

import (
	"bytes"
	"fmt"
	"log"
	"time"

	"github.com/hashicorp/terraform/helper/hashcode"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/helper/schema"
	"github.com/rackspace/gophercloud"
	"github.com/rackspace/gophercloud/openstack/compute/v2/extensions/bootfromvolume"
	"github.com/rackspace/gophercloud/openstack/compute/v2/extensions/floatingip"
	"github.com/rackspace/gophercloud/openstack/compute/v2/extensions/keypairs"
	"github.com/rackspace/gophercloud/openstack/compute/v2/extensions/secgroups"
	"github.com/rackspace/gophercloud/openstack/compute/v2/extensions/volumeattach"
	"github.com/rackspace/gophercloud/openstack/compute/v2/flavors"
	"github.com/rackspace/gophercloud/openstack/compute/v2/images"
	"github.com/rackspace/gophercloud/openstack/compute/v2/servers"
	"github.com/rackspace/gophercloud/openstack/networking/v2/extensions/layer3/floatingips"
	"github.com/rackspace/gophercloud/openstack/networking/v2/networks"
	"github.com/rackspace/gophercloud/openstack/networking/v2/ports"
)

func resourceComputeInstanceV2() *schema.Resource {
	return &schema.Resource{
		Create: resourceComputeInstanceV2Create,
		Read:   resourceComputeInstanceV2Read,
		Update: resourceComputeInstanceV2Update,
		Delete: resourceComputeInstanceV2Delete,

		Schema: map[string]*schema.Schema{
			"region": &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				DefaultFunc: envDefaultFunc("OS_REGION_NAME"),
			},
			"name": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
				ForceNew: false,
			},
			"image_id": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Computed:    true,
				DefaultFunc: envDefaultFunc("OS_IMAGE_ID"),
			},
			"image_name": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Computed:    true,
				DefaultFunc: envDefaultFunc("OS_IMAGE_NAME"),
			},
			"flavor_id": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    false,
				Computed:    true,
				DefaultFunc: envDefaultFunc("OS_FLAVOR_ID"),
			},
			"flavor_name": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    false,
				Computed:    true,
				DefaultFunc: envDefaultFunc("OS_FLAVOR_NAME"),
			},
			"security_groups": &schema.Schema{
				Type:     schema.TypeList,
				Optional: true,
				ForceNew: false,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
			"availability_zone": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
			},
			"network_service": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				DefaultFunc: envDefaultNetworkServiceFunc("OS_NETWORK_SERVICE"),
			},
			"network": &schema.Schema{
				Type:     schema.TypeList,
				Optional: true,
				ForceNew: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": &schema.Schema{
							Type:     schema.TypeString,
							Optional: true,
							Computed: true,
						},
						"uuid": &schema.Schema{
							Type:     schema.TypeString,
							Optional: true,
							Computed: true,
						},
						"port": &schema.Schema{
							Type:     schema.TypeString,
							Optional: true,
							Computed: true,
						},
						"fixed_ip_v4": &schema.Schema{
							Type:     schema.TypeString,
							Optional: true,
							Computed: true,
						},
						"fixed_ip_v6": &schema.Schema{
							Type:     schema.TypeString,
							Optional: true,
							Computed: true,
						},
						"floating_ip": &schema.Schema{
							Type:     schema.TypeString,
							Optional: true,
							ForceNew: false,
						},
						"mac": &schema.Schema{
							Type:     schema.TypeString,
							Computed: true,
						},
					},
				},
			},
			"metadata": &schema.Schema{
				Type:     schema.TypeMap,
				Optional: true,
				ForceNew: false,
			},
			"config_drive": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				ForceNew: true,
			},
			"admin_pass": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: false,
			},
			"access_ip_v4": &schema.Schema{
				Type:     schema.TypeString,
				Computed: true,
				Optional: true,
				ForceNew: false,
			},
			"access_ip_v6": &schema.Schema{
				Type:     schema.TypeString,
				Computed: true,
				Optional: true,
				ForceNew: false,
			},
			"key_pair": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
			},
			"block_device": &schema.Schema{
				Type:     schema.TypeList,
				Optional: true,
				ForceNew: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"uuid": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},
						"source_type": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},
						"volume_size": &schema.Schema{
							Type:     schema.TypeInt,
							Optional: true,
						},
						"destination_type": &schema.Schema{
							Type:     schema.TypeString,
							Optional: true,
						},
						"boot_index": &schema.Schema{
							Type:     schema.TypeInt,
							Optional: true,
						},
					},
				},
			},
			"volume": &schema.Schema{
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"id": &schema.Schema{
							Type:     schema.TypeString,
							Optional: true,
							Computed: true,
						},
						"volume_id": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},
						"device": &schema.Schema{
							Type:     schema.TypeString,
							Optional: true,
							Computed: true,
						},
					},
				},
				Set: resourceComputeVolumeAttachmentHash,
			},
		},
	}
}

func resourceComputeInstanceV2Create(d *schema.ResourceData, meta interface{}) error {
	config := meta.(*Config)

	computeClient, err := config.computeV2Client(d.Get("region").(string))
	if err != nil {
		return fmt.Errorf("Error creating OpenStack compute client: %s", err)
	}

	var createOpts servers.CreateOptsBuilder

	imageId, err := getImageID(computeClient, d)
	if err != nil {
		return err
	}

	flavorId, err := getFlavorID(computeClient, d)
	if err != nil {
		return err
	}

	networks, err := resourceInstanceNetworks(d, meta)
	if err != nil {
		return err
	}

	createOpts = &servers.CreateOpts{
		Name:             d.Get("name").(string),
		ImageRef:         imageId,
		FlavorRef:        flavorId,
		SecurityGroups:   resourceInstanceSecGroupsV2(d),
		AvailabilityZone: d.Get("availability_zone").(string),
		Networks:         networks,
		Metadata:         resourceInstanceMetadataV2(d),
		ConfigDrive:      d.Get("config_drive").(bool),
		AdminPass:        d.Get("admin_pass").(string),
	}

	if keyName, ok := d.Get("key_pair").(string); ok && keyName != "" {
		createOpts = &keypairs.CreateOptsExt{
			createOpts,
			keyName,
		}
	}

	if blockDeviceRaw, ok := d.Get("block_device").(map[string]interface{}); ok && blockDeviceRaw != nil {
		blockDevice := resourceInstanceBlockDeviceV2(d, blockDeviceRaw)
		createOpts = &bootfromvolume.CreateOptsExt{
			createOpts,
			blockDevice,
		}
	}

	log.Printf("[INFO] Requesting instance creation")
	server, err := servers.Create(computeClient, createOpts).Extract()
	if err != nil {
		return fmt.Errorf("Error creating OpenStack server: %s", err)
	}
	log.Printf("[INFO] Instance ID: %s", server.ID)

	// Store the ID now
	d.SetId(server.ID)

	// Wait for the instance to become running so we can get some attributes
	// that aren't available until later.
	log.Printf(
		"[DEBUG] Waiting for instance (%s) to become running",
		server.ID)

	stateConf := &resource.StateChangeConf{
		Pending:    []string{"BUILD"},
		Target:     "ACTIVE",
		Refresh:    ServerV2StateRefreshFunc(computeClient, server.ID),
		Timeout:    10 * time.Minute,
		Delay:      10 * time.Second,
		MinTimeout: 3 * time.Second,
	}

	_, err = stateConf.WaitForState()
	if err != nil {
		return fmt.Errorf(
			"Error waiting for instance (%s) to become ready: %s",
			server.ID, err)
	}

	// if a floating IP was specified, associate it to the instance
	rawNetworks := d.Get("network").([]interface{})

	network_service := d.Get("network_service").(string)
	switch network_service {
	case "neutron":
		networkingClient, err := config.networkingV2Client(d.Get("region").(string))
		if err != nil {
			return err
		}
		for _, raw := range rawNetworks {
			rawMap := raw.(map[string]interface{})
			if rawMap["floating_ip"].(string) != "" {
				log.Printf("[DEBUG] Attemping to associate %v to %v", rawMap["floating_ip"], d.Id())
				if err := associateFloatingIPNeutron(networkingClient, d.Id(), rawMap["uuid"].(string), rawMap["floating_ip"].(string)); err != nil {
					return err
				}
			}
		}
	case "nova-network":
		for _, raw := range rawNetworks {
			rawMap := raw.(map[string]interface{})
			if rawMap["floating_ip"].(string) != "" {
				log.Printf("[DEBUG] Attemping to associate %v to %v", rawMap["floating_ip"], d.Id())
				if err := associateFloatingIPNova(computeClient, d.Id(), rawMap["floating_ip"].(string)); err != nil {
					return err
				}
			}
		}
	default:
		return fmt.Errorf("Unsupported network service: %v", network_service)
	}

	// were volume attachments specified?
	if v := d.Get("volume"); v != nil {
		vols := v.(*schema.Set).List()
		if len(vols) > 0 {
			if blockClient, err := config.blockStorageV1Client(d.Get("region").(string)); err != nil {
				return fmt.Errorf("Error creating OpenStack block storage client: %s", err)
			} else {
				if err := attachVolumesToInstance(computeClient, blockClient, d.Id(), vols); err != nil {
					return err
				}
			}
		}
	}

	return resourceComputeInstanceV2Read(d, meta)
}

func resourceComputeInstanceV2Read(d *schema.ResourceData, meta interface{}) error {
	config := meta.(*Config)
	computeClient, err := config.computeV2Client(d.Get("region").(string))
	if err != nil {
		return fmt.Errorf("Error creating OpenStack compute client: %s", err)
	}

	server, err := servers.Get(computeClient, d.Id()).Extract()
	if err != nil {
		return CheckDeleted(d, err, "server")
	}

	log.Printf("[DEBUG] Retreived Server %s: %+v", d.Id(), server)

	d.Set("region", d.Get("region").(string))
	d.Set("name", server.Name)

	d.Set("access_ip_v4", server.AccessIPv4)
	d.Set("access_ip_v6", server.AccessIPv6)
	hostv4 := server.AccessIPv4
	hostv6 := server.AccessIPv6

	rawNetworks := d.Get("network").([]interface{})
	networks := make([]map[string]interface{}, len(rawNetworks))
	addresses := make(map[string]map[string]interface{})
	floatingIP := ""
	fallbackV4 := ""
	fallbackV6 := ""

	// gathering network information is a bit of a mess.
	// the networks block contains information from the user.
	//
	// the networks block is a numerical array.
	//
	// the server.Addresses block contains supplemental information.
	//
	// server.Addresses is keyed by the network name.
	//
	// the commonality between server.Addresses and the networks block is
	// the network name.
	//
	// So first, create a map indexed by the network name and gather the
	// useful information from server.Addresses
	for n, networkAddresses := range server.Addresses {
		addresses[n] = make(map[string]interface{})
		for _, element := range networkAddresses.([]interface{}) {
			address := element.(map[string]interface{})
			if address["OS-EXT-IPS:type"] == "floating" {
				addresses[n]["floating_ip"] = address["addr"]
				// grab the first floating IP found
				if floatingIP == "" {
					floatingIP = address["addr"].(string)
				}
			} else {
				if address["version"].(float64) == 4 {
					addresses[n]["fixed_ip_v4"] = address["addr"].(string)
					if fallbackV4 == "" {
						fallbackV4 = address["addr"].(string)
					}
				} else {
					addresses[n]["fixed_ip_v6"] = fmt.Sprintf("[%s]", address["addr"].(string))
					if fallbackV6 == "" {
						fallbackV6 = address["addr"].(string)
					}
				}
			}
			addresses[n]["mac"] = address["OS-EXT-IPS-MAC:mac_addr"].(string)
		}
	}

	log.Printf("[DEBUG] Addresses: %v", addresses)

	// if a floating IP was found above, use it
	if floatingIP != "" {
		hostv4 = floatingIP
	}

	// once all the server.Addresses info has been gathered,
	// loop through the network block and complement the existing information.
	for i, raw := range rawNetworks {
		rawMap := raw.(map[string]interface{})
		netName := rawMap["name"].(string)
		n := addresses[netName]

		if hostv4 == "" && n["fixed_ip_v4"] != nil {
			hostv4 = n["fixed_ip_v4"].(string)
		}

		if hostv6 == "" && n["fixed_ip_v6"] != nil {
			hostv6 = n["fixed_ip_v6"].(string)
		}

		networks[i] = map[string]interface{}{
			"uuid":        rawMap["uuid"],
			"name":        rawMap["name"],
			"port":        rawMap["port"],
			"fixed_ip_v4": n["fixed_ip_v4"],
			"fixed_ip_v6": n["fixed_ip_v6"],
			"floating_ip": n["floating_ip"],
			"mac":         n["mac"],
		}
	}

	// at this point, if hostv6 and hostv6 are still not set,
	// then someone launched an instance not specifying any networks
	// and just let the instance launch on the default network.
	// so we use the fallbackV*
	if hostv4 == "" {
		hostv4 = fallbackV4
	}

	if hostv6 == "" {
		hostv6 = fallbackV6
	}

	d.Set("network", networks)
	d.Set("access_ip_v4", hostv4)
	d.Set("access_ip_v6", hostv6)
	log.Printf("hostv4: %s", hostv4)
	log.Printf("hostv6: %s", hostv6)

	preferredv := ""
	if hostv4 != "" {
		preferredv = hostv4
	} else if hostv6 != "" {
		preferredv = hostv6
	}

	if preferredv != "" {
		// Initialize the connection info
		d.SetConnInfo(map[string]string{
			"type": "ssh",
			"host": preferredv,
		})
	}

	d.Set("metadata", server.Metadata)

	secGrpNames := []string{}
	for _, sg := range server.SecurityGroups {
		secGrpNames = append(secGrpNames, sg["name"].(string))
	}
	d.Set("security_groups", secGrpNames)

	flavorId, ok := server.Flavor["id"].(string)
	if !ok {
		return fmt.Errorf("Error setting OpenStack server's flavor: %v", server.Flavor)
	}
	d.Set("flavor_id", flavorId)

	flavor, err := flavors.Get(computeClient, flavorId).Extract()
	if err != nil {
		return err
	}
	d.Set("flavor_name", flavor.Name)

	imageId, ok := server.Image["id"].(string)
	if !ok {
		return fmt.Errorf("Error setting OpenStack server's image: %v", server.Image)
	}
	d.Set("image_id", imageId)

	image, err := images.Get(computeClient, imageId).Extract()
	if err != nil {
		return err
	}
	d.Set("image_name", image.Name)

	// volume attachments
	vas, err := getVolumeAttachments(computeClient, d.Id())
	if err != nil {
		return err
	}
	if len(vas) > 0 {
		attachments := make([]map[string]interface{}, len(vas))
		for i, attachment := range vas {
			attachments[i] = make(map[string]interface{})
			attachments[i]["id"] = attachment.ID
			attachments[i]["volume_id"] = attachment.VolumeID
			attachments[i]["device"] = attachment.Device
		}
		log.Printf("[INFO] Volume attachments: %v", attachments)
		d.Set("volume", attachments)
	}

	return nil
}

func resourceComputeInstanceV2Update(d *schema.ResourceData, meta interface{}) error {
	config := meta.(*Config)
	computeClient, err := config.computeV2Client(d.Get("region").(string))
	if err != nil {
		return fmt.Errorf("Error creating OpenStack compute client: %s", err)
	}

	var updateOpts servers.UpdateOpts
	if d.HasChange("name") {
		updateOpts.Name = d.Get("name").(string)
	}
	if d.HasChange("access_ip_v4") {
		updateOpts.AccessIPv4 = d.Get("access_ip_v4").(string)
	}
	if d.HasChange("access_ip_v6") {
		updateOpts.AccessIPv4 = d.Get("access_ip_v6").(string)
	}

	if updateOpts != (servers.UpdateOpts{}) {
		_, err := servers.Update(computeClient, d.Id(), updateOpts).Extract()
		if err != nil {
			return fmt.Errorf("Error updating OpenStack server: %s", err)
		}
	}

	if d.HasChange("metadata") {
		var metadataOpts servers.MetadataOpts
		metadataOpts = make(servers.MetadataOpts)
		newMetadata := d.Get("metadata").(map[string]interface{})
		for k, v := range newMetadata {
			metadataOpts[k] = v.(string)
		}

		_, err := servers.UpdateMetadata(computeClient, d.Id(), metadataOpts).Extract()
		if err != nil {
			return fmt.Errorf("Error updating OpenStack server (%s) metadata: %s", d.Id(), err)
		}
	}

	if d.HasChange("security_groups") {
		oldSGRaw, newSGRaw := d.GetChange("security_groups")
		oldSGSlice, newSGSlice := oldSGRaw.([]interface{}), newSGRaw.([]interface{})
		oldSGSet := schema.NewSet(func(v interface{}) int { return hashcode.String(v.(string)) }, oldSGSlice)
		newSGSet := schema.NewSet(func(v interface{}) int { return hashcode.String(v.(string)) }, newSGSlice)
		secgroupsToAdd := newSGSet.Difference(oldSGSet)
		secgroupsToRemove := oldSGSet.Difference(newSGSet)

		log.Printf("[DEBUG] Security groups to add: %v", secgroupsToAdd)

		log.Printf("[DEBUG] Security groups to remove: %v", secgroupsToRemove)

		for _, g := range secgroupsToAdd.List() {
			err := secgroups.AddServerToGroup(computeClient, d.Id(), g.(string)).ExtractErr()
			if err != nil {
				return fmt.Errorf("Error adding security group to OpenStack server (%s): %s", d.Id(), err)
			}
			log.Printf("[DEBUG] Added security group (%s) to instance (%s)", g.(string), d.Id())
		}

		for _, g := range secgroupsToRemove.List() {
			err := secgroups.RemoveServerFromGroup(computeClient, d.Id(), g.(string)).ExtractErr()
			if err != nil {
				errCode, ok := err.(*gophercloud.UnexpectedResponseCodeError)
				if !ok {
					return fmt.Errorf("Error removing security group from OpenStack server (%s): %s", d.Id(), err)
				}
				if errCode.Actual == 404 {
					continue
				} else {
					return fmt.Errorf("Error removing security group from OpenStack server (%s): %s", d.Id(), err)
				}
			} else {
				log.Printf("[DEBUG] Removed security group (%s) from instance (%s)", g.(string), d.Id())
			}
		}
	}

	if d.HasChange("admin_pass") {
		if newPwd, ok := d.Get("admin_pass").(string); ok {
			err := servers.ChangeAdminPassword(computeClient, d.Id(), newPwd).ExtractErr()
			if err != nil {
				return fmt.Errorf("Error changing admin password of OpenStack server (%s): %s", d.Id(), err)
			}
		}
	}

	if d.HasChange("network") {
		log.Printf("[DEBUG] Detected network change.")
		oldNets, newNets := d.GetChange("network")

		network_service := d.Get("network_service").(string)
		switch network_service {
		case "neutron":
			networkingClient, err := config.networkingV2Client(d.Get("region").(string))
			if err != nil {
				return nil
			}
			// first disassociate
			rawNetworks := oldNets.([]interface{})
			for _, raw := range rawNetworks {
				rawMap := raw.(map[string]interface{})
				if rawMap["floating_ip"].(string) != "" {
					log.Printf("[DEBUG] Attemping to disassociate %v from %v", rawMap["floating_ip"], d.Id())
					if err := disassociateFloatingIPNeutron(networkingClient, d.Id(), rawMap["uuid"].(string), rawMap["floating_ip"].(string)); err != nil {
						return err
					}
				}
			}

			// then associate
			rawNetworks = newNets.([]interface{})
			for _, raw := range rawNetworks {
				rawMap := raw.(map[string]interface{})
				if rawMap["floating_ip"].(string) != "" {
					log.Printf("[DEBUG] Attemping to associate %v to %v", rawMap["floating_ip"], d.Id())
					if err := associateFloatingIPNeutron(networkingClient, d.Id(), rawMap["uuid"].(string), rawMap["floating_ip"].(string)); err != nil {
						return err
					}
				}
			}
		case "nova-network":
			// first disassociate
			rawNetworks := oldNets.([]interface{})
			for _, raw := range rawNetworks {
				rawMap := raw.(map[string]interface{})
				if rawMap["floating_ip"].(string) != "" {
					log.Printf("[DEBUG] Attemping to disassociate %v from %v", rawMap["floating_ip"], d.Id())
					if err := disassociateFloatingIPNova(computeClient, d.Id(), rawMap["floating_ip"].(string)); err != nil {
						return err
					}
				}
			}

			// then associate
			rawNetworks = newNets.([]interface{})
			for _, raw := range rawNetworks {
				rawMap := raw.(map[string]interface{})
				if rawMap["floating_ip"].(string) != "" {
					log.Printf("[DEBUG] Attemping to associate %v to %v", rawMap["floating_ip"], d.Id())
					if err := associateFloatingIPNova(computeClient, d.Id(), rawMap["floating_ip"].(string)); err != nil {
						return err
					}
				}
			}
		default:
			return fmt.Errorf("Unsupported network service: %v", network_service)
		}

		d.SetPartial("network")
	}

	if d.HasChange("volume") {
		// old attachments and new attachments
		oldAttachments, newAttachments := d.GetChange("volume")

		// for each old attachment, detach the volume
		oldAttachmentSet := oldAttachments.(*schema.Set).List()
		if len(oldAttachmentSet) > 0 {
			if blockClient, err := config.blockStorageV1Client(d.Get("region").(string)); err != nil {
				return err
			} else {
				if err := detachVolumesFromInstance(computeClient, blockClient, d.Id(), oldAttachmentSet); err != nil {
					return err
				}
			}
		}

		// for each new attachment, attach the volume
		newAttachmentSet := newAttachments.(*schema.Set).List()
		if len(newAttachmentSet) > 0 {
			if blockClient, err := config.blockStorageV1Client(d.Get("region").(string)); err != nil {
				return err
			} else {
				if err := attachVolumesToInstance(computeClient, blockClient, d.Id(), newAttachmentSet); err != nil {
					return err
				}
			}
		}

		d.SetPartial("volume")
	}

	if d.HasChange("flavor_id") || d.HasChange("flavor_name") {
		flavorId, err := getFlavorID(computeClient, d)
		if err != nil {
			return err
		}
		resizeOpts := &servers.ResizeOpts{
			FlavorRef: flavorId,
		}
		err = servers.Resize(computeClient, d.Id(), resizeOpts).ExtractErr()
		if err != nil {
			return fmt.Errorf("Error resizing OpenStack server: %s", err)
		}

		// Wait for the instance to finish resizing.
		log.Printf("[DEBUG] Waiting for instance (%s) to finish resizing", d.Id())

		stateConf := &resource.StateChangeConf{
			Pending:    []string{"RESIZE"},
			Target:     "VERIFY_RESIZE",
			Refresh:    ServerV2StateRefreshFunc(computeClient, d.Id()),
			Timeout:    3 * time.Minute,
			Delay:      10 * time.Second,
			MinTimeout: 3 * time.Second,
		}

		_, err = stateConf.WaitForState()
		if err != nil {
			return fmt.Errorf("Error waiting for instance (%s) to resize: %s", d.Id(), err)
		}

		// Confirm resize.
		log.Printf("[DEBUG] Confirming resize")
		err = servers.ConfirmResize(computeClient, d.Id()).ExtractErr()
		if err != nil {
			return fmt.Errorf("Error confirming resize of OpenStack server: %s", err)
		}

		stateConf = &resource.StateChangeConf{
			Pending:    []string{"VERIFY_RESIZE"},
			Target:     "ACTIVE",
			Refresh:    ServerV2StateRefreshFunc(computeClient, d.Id()),
			Timeout:    3 * time.Minute,
			Delay:      10 * time.Second,
			MinTimeout: 3 * time.Second,
		}

		_, err = stateConf.WaitForState()
		if err != nil {
			return fmt.Errorf("Error waiting for instance (%s) to confirm resize: %s", d.Id(), err)
		}
	}

	return resourceComputeInstanceV2Read(d, meta)
}

func resourceComputeInstanceV2Delete(d *schema.ResourceData, meta interface{}) error {
	config := meta.(*Config)
	computeClient, err := config.computeV2Client(d.Get("region").(string))
	if err != nil {
		return fmt.Errorf("Error creating OpenStack compute client: %s", err)
	}

	err = servers.Delete(computeClient, d.Id()).ExtractErr()
	if err != nil {
		return fmt.Errorf("Error deleting OpenStack server: %s", err)
	}

	// Wait for the instance to delete before moving on.
	log.Printf("[DEBUG] Waiting for instance (%s) to delete", d.Id())

	stateConf := &resource.StateChangeConf{
		Pending:    []string{"ACTIVE"},
		Target:     "DELETED",
		Refresh:    ServerV2StateRefreshFunc(computeClient, d.Id()),
		Timeout:    10 * time.Minute,
		Delay:      10 * time.Second,
		MinTimeout: 3 * time.Second,
	}

	_, err = stateConf.WaitForState()
	if err != nil {
		return fmt.Errorf(
			"Error waiting for instance (%s) to delete: %s",
			d.Id(), err)
	}

	d.SetId("")
	return nil
}

// ServerV2StateRefreshFunc returns a resource.StateRefreshFunc that is used to watch
// an OpenStack instance.
func ServerV2StateRefreshFunc(client *gophercloud.ServiceClient, instanceID string) resource.StateRefreshFunc {
	return func() (interface{}, string, error) {
		s, err := servers.Get(client, instanceID).Extract()
		if err != nil {
			errCode, ok := err.(*gophercloud.UnexpectedResponseCodeError)
			if !ok {
				return nil, "", err
			}
			if errCode.Actual == 404 {
				return s, "DELETED", nil
			}
			return nil, "", err
		}

		return s, s.Status, nil
	}
}

func resourceInstanceSecGroupsV2(d *schema.ResourceData) []string {
	rawSecGroups := d.Get("security_groups").([]interface{})
	secgroups := make([]string, len(rawSecGroups))
	for i, raw := range rawSecGroups {
		secgroups[i] = raw.(string)
	}
	return secgroups
}

func resourceInstanceNetworks(d *schema.ResourceData, meta interface{}) ([]servers.Network, error) {

	rawNetworks := d.Get("network").([]interface{})
	networks := make([]servers.Network, len(rawNetworks))
	newNetworks := make([]map[string]interface{}, len(rawNetworks))

	network_service := d.Get("network_service").(string)
	switch network_service {
	case "neutron":
		config := meta.(*Config)
		networkingClient, err := config.networkingV2Client(d.Get("region").(string))
		if err != nil {
			return nil, err
		}

		for i, raw := range rawNetworks {
			rawMap := raw.(map[string]interface{})

			networkDetails, err := getNeutronNetwork(networkingClient, rawMap)
			if err != nil {
				return nil, err
			}

			networks[i] = servers.Network{
				UUID:    networkDetails.ID,
				Port:    rawMap["port"].(string),
				FixedIP: rawMap["fixed_ip_v4"].(string),
			}

			newNetworks[i] = map[string]interface{}{
				"uuid":        networkDetails.ID,
				"name":        networkDetails.Name,
				"port":        rawMap["port"],
				"fixed_ip_v4": rawMap["fixed_ip_v4"],
				"floating_ip": rawMap["floating_ip"],
			}
		}
	case "nova-network":
		for i, raw := range rawNetworks {
			rawMap := raw.(map[string]interface{})

			// at this time, gophercloud does not support the os-network extension,
			// so looking up a network by its name can't happen.
			networks[i] = servers.Network{
				UUID:    rawMap["uuid"].(string),
				FixedIP: rawMap["fixed_ip_v4"].(string),
			}

			newNetworks[i] = map[string]interface{}{
				"uuid":        rawMap["uuid"].(string),
				"name":        rawMap["name"].(string),
				"fixed_ip_v4": rawMap["fixed_ip_v4"],
				"floating_ip": rawMap["floating_ip"],
			}
		}
	default:
		return nil, fmt.Errorf("Unsupported network service: %v", network_service)
	}

	// feed the networks with added info back into the resource
	d.Set("network", newNetworks)

	return networks, nil
}

func getNeutronNetwork(networkingClient *gophercloud.ServiceClient, netInfo map[string]interface{}) (networks.Network, error) {
	var neutronNet networks.Network

	allPages, err := networks.List(networkingClient, networks.ListOpts{
		Name: netInfo["name"].(string),
		ID:   netInfo["uuid"].(string),
	}).AllPages()
	if err != nil {
		return neutronNet, err
	}

	networkList, err := networks.ExtractNetworks(allPages)
	if err != nil {
		return neutronNet, err
	}

	for _, network := range networkList {
		neutronNet = network
	}

	return neutronNet, nil
}

func associateFloatingIPNeutron(networkingClient *gophercloud.ServiceClient, serverID, networkID, floatingIP string) error {
	fipID, err := getFloatingIPIDNeutron(networkingClient, floatingIP)
	if err != nil {
		return err
	}

	portID, err := getInstancePortIDNeutron(networkingClient, serverID, networkID)
	if err != nil {
		return err
	}

	_, err = floatingips.Update(networkingClient, fipID, floatingips.UpdateOpts{
		PortID: portID,
	}).Extract()
	if err != nil {
		return err
	}

	return nil
}

func disassociateFloatingIPNeutron(networkingClient *gophercloud.ServiceClient, serverID, networkID, floatingIP string) error {
	fipID, err := getFloatingIPIDNeutron(networkingClient, floatingIP)
	if err != nil {
		return err
	}

	portID := ""

	_, err = floatingips.Update(networkingClient, fipID, floatingips.UpdateOpts{
		PortID: portID,
	}).Extract()
	if err != nil {
		return err
	}

	return nil
}

func associateFloatingIPNova(computeClient *gophercloud.ServiceClient, serverID, floatingIP string) error {
	if err := floatingip.Associate(computeClient, serverID, floatingIP).ExtractErr(); err != nil {
		return fmt.Errorf("Error associating Floating IP: %s", err)
	}
	return nil
}

func disassociateFloatingIPNova(computeClient *gophercloud.ServiceClient, serverID, floatingIP string) error {
	if err := floatingip.Disassociate(computeClient, serverID, floatingIP).ExtractErr(); err != nil {
		return fmt.Errorf("Error disassociating Floating IP: %s", err)
	}
	return nil
}

func getInstancePortIDNeutron(networkingClient *gophercloud.ServiceClient, instanceID, networkID string) (string, error) {
	var portID string

	allPages, err := ports.List(networkingClient, ports.ListOpts{
		DeviceID:  instanceID,
		NetworkID: networkID,
	}).AllPages()
	if err != nil {
		return "", err
	}

	portList, err := ports.ExtractPorts(allPages)
	if err != nil {
		return "", err
	}

	for _, port := range portList {
		portID = port.ID
	}

	return portID, nil
}

func getFloatingIPIDNeutron(networkingClient *gophercloud.ServiceClient, fip string) (string, error) {
	ips := []floatingips.FloatingIP{}

	allPages, err := floatingips.List(networkingClient, floatingips.ListOpts{
		FloatingIP: fip,
	}).AllPages()
	if err != nil {
		return "", err
	}

	floatingipList, err := floatingips.ExtractFloatingIPs(allPages)
	if err != nil {
		return "", err
	}

	for _, f := range floatingipList {
		ips = append(ips, f)
	}

	if len(ips) > 1 {
		return "", fmt.Errorf("More than one floating IP found.")
	}

	floatingIP := ips[0]
	floatingIPID := floatingIP.ID
	return floatingIPID, nil
}

func resourceInstanceMetadataV2(d *schema.ResourceData) map[string]string {
	m := make(map[string]string)
	for key, val := range d.Get("metadata").(map[string]interface{}) {
		m[key] = val.(string)
	}
	return m
}

func resourceInstanceBlockDeviceV2(d *schema.ResourceData, bd map[string]interface{}) []bootfromvolume.BlockDevice {
	sourceType := bootfromvolume.SourceType(bd["source_type"].(string))
	bfvOpts := []bootfromvolume.BlockDevice{
		bootfromvolume.BlockDevice{
			UUID:            bd["uuid"].(string),
			SourceType:      sourceType,
			VolumeSize:      bd["volume_size"].(int),
			DestinationType: bd["destination_type"].(string),
			BootIndex:       bd["boot_index"].(int),
		},
	}

	return bfvOpts
}

func getImageID(client *gophercloud.ServiceClient, d *schema.ResourceData) (string, error) {
	imageId := d.Get("image_id").(string)

	if imageId != "" {
		return imageId, nil
	}

	imageCount := 0
	imageName := d.Get("image_name").(string)

	if imageName != "" {
		allPages, err := images.ListDetail(client, &images.ListOpts{
			Name: imageName,
		}).AllPages()
		if err != nil {
			return "", nil
		}

		imageList, err := images.ExtractImages(allPages)
		if err != nil {
			return "", err
		}

		for _, i := range imageList {
			if i.Name == imageName {
				imageCount++
				imageId = i.ID
			}
		}

		switch imageCount {
		case 0:
			return "", fmt.Errorf("Unable to find image: %s", imageName)
		case 1:
			return imageId, nil
		default:
			return "", fmt.Errorf("Found %d images matching %s", imageCount, imageName)
		}
	}
	return "", fmt.Errorf("Neither an image ID nor an image name were able to be determined.")
}

func getFlavorID(client *gophercloud.ServiceClient, d *schema.ResourceData) (string, error) {
	flavorId := d.Get("flavor_id").(string)

	if flavorId != "" {
		return flavorId, nil
	}

	flavorCount := 0
	flavorName := d.Get("flavor_name").(string)

	if flavorName != "" {
		allPages, err := flavors.ListDetail(client, nil).AllPages()
		if err != nil {
			return "", err
		}

		flavorList, err := flavors.ExtractFlavors(allPages)
		if err != nil {
			return "", err
		}

		for _, f := range flavorList {
			if f.Name == flavorName {
				flavorCount++
				flavorId = f.ID
			}
		}

		switch flavorCount {
		case 0:
			return "", fmt.Errorf("Unable to find flavor: %s", flavorName)
		case 1:
			return flavorId, nil
		default:
			return "", fmt.Errorf("Found %d flavors matching %s", flavorCount, flavorName)
		}
	}
	return "", fmt.Errorf("Neither a flavor ID nor a flavor name were able to be determined.")
}

func resourceComputeVolumeAttachmentHash(v interface{}) int {
	var buf bytes.Buffer
	m := v.(map[string]interface{})
	buf.WriteString(fmt.Sprintf("%s-", m["volume_id"].(string)))
	buf.WriteString(fmt.Sprintf("%s-", m["device"].(string)))
	return hashcode.String(buf.String())
}

func attachVolumesToInstance(computeClient *gophercloud.ServiceClient, blockClient *gophercloud.ServiceClient, serverId string, vols []interface{}) error {
	if len(vols) > 0 {
		for _, v := range vols {
			va := v.(map[string]interface{})
			volumeId := va["volume_id"].(string)
			device := va["device"].(string)

			s := ""
			if serverId != "" {
				s = serverId
			} else if va["server_id"] != "" {
				s = va["server_id"].(string)
			} else {
				return fmt.Errorf("Unable to determine server ID to attach volume.")
			}

			vaOpts := &volumeattach.CreateOpts{
				Device:   device,
				VolumeID: volumeId,
			}

			if _, err := volumeattach.Create(computeClient, s, vaOpts).Extract(); err != nil {
				return err
			}

			stateConf := &resource.StateChangeConf{
				Target:     "in-use",
				Refresh:    VolumeV1StateRefreshFunc(blockClient, va["volume_id"].(string)),
				Timeout:    30 * time.Minute,
				Delay:      5 * time.Second,
				MinTimeout: 2 * time.Second,
			}

			if _, err := stateConf.WaitForState(); err != nil {
				return err
			}

			log.Printf("[INFO] Attached volume %s to instance %s", volumeId, serverId)
		}
	}
	return nil
}

func detachVolumesFromInstance(computeClient *gophercloud.ServiceClient, blockClient *gophercloud.ServiceClient, serverId string, vols []interface{}) error {
	if len(vols) > 0 {
		for _, v := range vols {
			va := v.(map[string]interface{})
			aId := va["id"].(string)

			if err := volumeattach.Delete(computeClient, serverId, aId).ExtractErr(); err != nil {
				return err
			}

			stateConf := &resource.StateChangeConf{
				Target:     "available",
				Refresh:    VolumeV1StateRefreshFunc(blockClient, va["volume_id"].(string)),
				Timeout:    30 * time.Minute,
				Delay:      5 * time.Second,
				MinTimeout: 2 * time.Second,
			}

			if _, err := stateConf.WaitForState(); err != nil {
				return err
			}
			log.Printf("[INFO] Detached volume %s from instance %s", va["volume_id"], serverId)
		}
	}

	return nil
}

func getVolumeAttachments(computeClient *gophercloud.ServiceClient, serverId string) ([]volumeattach.VolumeAttachment, error) {
	var attachments []volumeattach.VolumeAttachment
	allPages, err := volumeattach.List(computeClient, serverId).AllPages()
	if err != nil {
		return attachments, err
	}

	attachments, err = volumeattach.ExtractVolumeAttachments(allPages)
	if err != nil {
		return attachments, err
	}

	return attachments, nil
}
