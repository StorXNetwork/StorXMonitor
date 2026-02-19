# This file enhance the normal docker-bake.hcl (docker can combine the two) with publishing images, and publishing build cached.
# Should be used only for main builds.

target "storagenode-modular" {
  cache-to = [
    {
      type = "registry",
      mode = "min",
      ref  = "ghcr.io/storxnetwork/storagenode-modular-cache:main"
    }
  ]
}


target "satellite-modular" {
  cache-to = [
    {
      type = "registry",
      mode = "min",
      ref  = "ghcr.io/storxnetwork/satellite-modular-cache:main"
    }
  ]
}

target "storagenode-ui" {
  cache-to = [
    {
      type = "registry",
      mode = "min",
      ref  = "ghcr.io/storxnetwork/storagenode-ui-cache:main"
    }
  ]
}

target "satellite-ui" {
  cache-to = [
    {
      type = "registry",
      mode = "min",
      ref  = "ghcr.io/storxnetwork/satellite-ui-cache:main"
    }
  ]
}
