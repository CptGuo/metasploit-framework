# -*- coding: binary -*-

module Msf

###
#
# This module provides methods for modules which intend to handle multiple hosts
# themselves through some means, e.g. scanners. This circumvents the typical
# RHOSTS -> RHOST logic offered by the framework.
#
###

module Auxiliary::MultipleTargetHosts

  def has_check?
    respond_to?(:check_host)
  end

  def check
    return Exploit::CheckCode::Unsupported unless has_check?

    nmod = replicant
    nmod.check_host(datastore['RHOST'])
  end

end
end
