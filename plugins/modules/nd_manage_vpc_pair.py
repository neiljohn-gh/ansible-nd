#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Neil John (@neijohn) <neijohn@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type
__copyright__ = "Copyright (c) 2025 Cisco and/or its affiliates."
__author__ = "Neil John"

DOCUMENTATION = """
---
module: nd_manage_vpc_pairs
short_description: Manage vPC pairs in Nexus devices.
version_added: "1.0.0"
author: Neil John (@neijohn)
description:
- Create, update, delete, override, and query vPC pairs on Nexus devices.
- Supports state-based operations with intelligent diff calculation for optimal API calls.
- Uses Pydantic model validation for vPC pair configurations.
options:
    state:
        choices:
        - merged
        - replaced
        - deleted
        - overridden
        - query
        default: merged
        description:
        - The state of the vPC pair configuration after module completion.
        type: str
    config:
        description:
        - A list of vPC pair configuration dictionaries.
        type: list
        elements: dict
        suboptions:
            peer1_switch_id:
                description:
                - peer1 switch serial number for the vPC pair.
                - Must be a valid switch serial number.
                required: true
                type: str
            peer2_switch_id:
                description:
                - peer2 switch serial number for the vPC pair.
                - Must be a valid switch serial number.
                required: true
                type: str
            use_virtual_Pair_link:
                description:
                - Enable virtual pair link for the vPC pair.
                - When true, virtual pair link is present and configured.
                - When false, physical pair link is used.
                type: bool
                default: true
"""

EXAMPLES = """
# Create a new vPC pair with virtual pair link
- name: Create vPC pair with virtual pair link
  cisco.nd.nd_manage_vpc_pairs:
    state: merged
    config:
      - peer1_switch_id: "FDO23040Q85"
        peer2_switch_id: "FDO23040Q86"
        use_virtual_Pair_link: true

# Create a vPC pair with physical pair link
- name: Create vPC pair with physical pair link
  cisco.nd.nd_manage_vpc_pairs:
    state: merged
    config:
      - peer1_switch_id: "FDO23040Q87"
        peer2_switch_id: "FDO23040Q88"
        use_virtual_Pair_link: false

# Create multiple vPC pairs
- name: Create multiple vPC pairs
  cisco.nd.nd_manage_vpc_pairs:
    state: merged
    config:
      - peer1_switch_id: "FDO23040Q85"
        peer2_switch_id: "FDO23040Q86"
        use_virtual_Pair_link: true
      - peer1_switch_id: "FDO23040Q87"
        peer2_switch_id: "FDO23040Q88"
        use_virtual_Pair_link: false

# Replace existing vPC pair configuration
- name: Replace vPC pair configuration
  cisco.nd.nd_manage_vpc_pairs:
    state: replaced
    config:
      - peer1_switch_id: "FDO23040Q85"
        peer2_switch_id: "FDO23040Q86"
        use_virtual_Pair_link: false

# Delete a specific vPC pair
- name: Delete vPC pair
  cisco.nd.nd_manage_vpc_pairs:
    state: deleted
    config:
      - peer1_switch_id: "FDO23040Q85"
        peer2_switch_id: "FDO23040Q86"

# Query existing vPC pairs
- name: Query all vPC pairs
  cisco.nd.nd_manage_vpc_pairs:
    state: query

# Query specific vPC pair
- name: Query specific vPC pair
  cisco.nd.nd_manage_vpc_pairs:
    state: query
    config:
      - peer1_switch_id: "FDO23040Q85"
        peer2_switch_id: "FDO23040Q86"

# Override vPC pair configurations (replace all with specified configs)
- name: Override all vPC pair configurations
  cisco.nd.nd_manage_vpc_pairs:
    state: overridden
    config:
      - peer1_switch_id: "FDO23040Q85"
        peer2_switch_id: "FDO23040Q86"
        use_virtual_Pair_link: true
      - peer1_switch_id: "FDO23040Q89"
        peer2_switch_id: "FDO23040Q90"
        use_virtual_Pair_link: false

# Override without any new vPC pairs (delete all existing)
- name: Override without any new vPC pairs
  cisco.nd.nd_manage_vpc_pairs:
    state: overridden
"""

RETURN = """
changed:
    description: Whether the module made any changes
    type: bool
    returned: always
    sample: true
diff:
    description: List of differences between desired and current state
    type: list
    returned: always
    sample: []
response:
    description: API response from the Nexus Dashboard
    type: list
    returned: always
    sample: []
warnings:
    description: List of warning messages
    type: list
    returned: when applicable
    sample: []
query:
    description: Current state of vPC pairs (only returned in query state)
    type: list
    returned: when state is query
    sample: [
        {
            "peer1SwitchId": "FDO23040Q85",
            "peer2SwitchId": "FDO23040Q86",
            "useVirtualPeerLink": true
        }
    ]
"""

import copy
import inspect
import logging
import re
import traceback
import sys
import json

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import NDModule
from ansible.module_utils.basic import missing_required_lib

from ..module_utils.common.log import Log
from ..module_utils.common.models import merge_models, model_payload_with_defaults
from ansible_collections.cisco.nd.plugins.module_utils.manage.vpc_pair.model_playbook_vpc_pair import VpcPairModel

try:
    from deepdiff import DeepDiff
except ImportError:
    HAS_DEEPDIFF = False
    DEEPDIFF_IMPORT_ERROR = traceback.format_exc()
else:
    HAS_DEEPDIFF = True
    DEEPDIFF_IMPORT_ERROR = None

class UpdateInventory:
    """
    Class to update the Ansible inventory with vPC pair information.

    This class is responsible for updating the Ansible inventory with the current state
    of switches retrieved from Nexus Dashboard (ND).

    Attributes:
        nd: Nexus Dashboard instance for making API requests.
        switches: List of SwitchModel objects representing the current state of switches.
        logger: Logger instance for logging debug information.
        path: API endpoint path for retrieving switch information.
        verb: HTTP method used for the request (GET).
        sw_sn_from_ip: Dictionary mapping switch IP addresses to serial numbers.
    """

    def __init__(self, nd, logger=None):
        self.class_name = self.__class__.__name__
        self.nd = nd
        self.switches = []
        self.logger = logger or logging.getLogger(f"nd.{self.class_name}")
        self.path = f"/api/v1/manage/fabrics/{self.nd.params.get('fabric')}/switches"
        self.verb = "GET"
        self.sw_sn_from_ip = {}

    def refresh(self):
        """
        Refreshes the switch state by fetching the latest data from the ND API.

        This method updates the internal switches attribute with fresh data
        retrieved from the network controller using the configured path and HTTP verb.

        Returns:
            None: Updates the self.switches attribute directly.
        """
        self.logger.debug("Fetching switch state from ND API at path: %s with verb: %s", self.path, self.verb)
        response = self.nd.request(self.path, method=self.verb)
        self.switches = response.get("switches", [])
        if not self.switches:
            self.logger.warning("No switches found in the response from ND API.")
            return
        self.logger.debug("Switch state retrieved: %s", json.dumps(self.switches, indent=2))
        # Create switch ip to serial number mapping
        self.sw_sn_from_ip = {sw["fabricManagementIp"]: sw["serialNumber"] for sw in self.switches if "fabricManagementIp" in sw and "serialNumber" in sw}
        self.logger.debug("Switch IP to Serial Number mapping created: %s", self.sw_sn_from_ip)

class GetWant:
    """
    Class to retrieve and process vPC pair configurations from Ansible task parameters.

    This class handles the retrieval of vPC pair configurations from the task parameters
    and prepares them for processing.
    Attributes:
        class_name (str): Name of the class.
        log (Logger): Logger instance for this class.
        task_params (dict): Parameters provided from the Ansible task.
        vpc_pairs (list): List of VpcPairModel objects representing the desired state of vPC pairs.
    Methods:
        validate_task_params(): Validates the task parameters and builds the desired state using utility functions.
    """

    def __init__(self, inventory, task_params, logger=None):
        self.class_name = self.__class__.__name__
        self.log = logger or logging.getLogger(f"nd.{self.class_name}")
        self.task_params = task_params
        self.vpc_pairs = []
        self.inventory = inventory

        msg = "ENTERED GetWant(): "
        self.log.debug(msg)
        
    def validate_task_params(self):
        """
        Validates and processes task parameters to create vPC pair model objects.

        This method iterates through each vPC pair configuration in the task parameters
        and converts them into VpcPairModel instances based on the provided configurations.
        The resulting models are stored in the want list for further processing.

        Returns:
            None: Updates self.want list with processed VpcPairModel objects
        """
        self.class_name = self.__class__.__name__
        method_name = inspect.stack()[0][3]
        msg = f"ENTERED: {self.class_name}.{method_name}"
        self.log.debug(msg)
        used_switch_ids = set()
        for vpc_pair in self.task_params.get("config", []):
            vpc_pair["peer1_switch_id"] = self.inventory.sw_sn_from_ip.get(vpc_pair["peer1_switch_id"], vpc_pair["peer1_switch_id"])
            vpc_pair["peer2_switch_id"] = self.inventory.sw_sn_from_ip.get(vpc_pair["peer2_switch_id"], vpc_pair["peer2_switch_id"])
            if vpc_pair["peer1_switch_id"] == vpc_pair["peer2_switch_id"]:
                raise ValueError(f"peer1_switch_id and peer2_switch_id cannot be the same: {vpc_pair['peer1_switch_id']}")
            if vpc_pair["peer1_switch_id"] in used_switch_ids or vpc_pair["peer2_switch_id"] in used_switch_ids:
                raise ValueError(f"Switch IDs must be unique across vPC pairs: {vpc_pair['peer1_switch_id']} and {vpc_pair['peer2_switch_id']}")
            used_switch_ids.add(vpc_pair["peer1_switch_id"])
            used_switch_ids.add(vpc_pair["peer2_switch_id"])
            validated_config = VpcPairModel.get_model(vpc_pair)
            self.vpc_pairs.append(validated_config)
        self.log.debug("Processed vPC pair configurations: %s", self.vpc_pairs)

class GetHave:
    """
    Class to retrieve and process vPC pair state information from Nexus Dashboard (ND).

    This class handles the retrieval of vPC pair state information from the Nexus Dashboard
    API and processes the response into a list of VpcPairModel objects.

    Attributes:
        class_name (str): Name of the class.
        log (Logger): Logger instance for this class.
        fabric (str): Fabric name to query vPC pairs for.
        path (str): API endpoint path for vPC pair information.
        recommendation_path (str): API endpoint path for vPC pair recommendations used for virtual peer link.
        verb (str): HTTP method used for the request (GET).
        vpc_pair_state (dict): Raw vPC pair state data retrieved from ND.
        vpc_pairs (list): List of processed VpcPairModel objects.
        nd: Nexus Dashboard instance for making API requests.
        sw_sn_from_ip (dict): Mapping of switch IP addresses to serial numbers.

    Methods:
        refresh(): Fetches the current vPC pair state from Nexus Dashboard.
        validate_nd_state(): Processes the vPC pair state data into VpcPairModel objects.
        get_virtual_peer_link_details(): Retrieves virtual peer link details for vPC pairs.
    """

    def __init__(self, nd, inventory, logger=None):
        self.class_name = self.__class__.__name__
        self.log = logger or logging.getLogger(f"nd.{self.class_name}")
        self.fabric = nd.params.get("fabric")
        self.path = f"/api/v1/manage/fabrics/{self.fabric}/vpcPairs"
        self.recommendation_path = "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/vpcpair/recommendation?serialNumber="
        self.verb = "GET"
        self.vpc_pair_state = {}
        self.vpc_pairs = []
        self.nd = nd
        self.sw_sn_from_ip = inventory.sw_sn_from_ip

        msg = "ENTERED GetHave(): "
        self.log.debug(msg)

    def refresh(self):
        """
        Refreshes the vPC pair state by fetching the latest data from the ND API.

        This method updates the internal vpc_pair_state attribute with fresh data
        retrieved from the network controller using the configured path and HTTP verb.

        Returns:
            None: Updates the self.vpc_pair_state attribute directly.
        """
        self.class_name = self.__class__.__name__
        method_name = inspect.stack()[0][3]  # pylint: disable=unused-variable

        msg = f"ENTERED: {self.class_name}.{method_name}"
        self.log.debug(msg)
        self.log.debug("Fetching vPC pair state from ND API at path: %s with verb: %s", self.path, self.verb)
        self.vpc_pair_state = self.nd.request(self.path, method=self.verb)
        self.vpc_pair_list = self.vpc_pair_state.get("vpcPairs", [])
        self.get_virtual_peer_link_details()
        self.log.debug("vPC pair state retrieved: %s", json.dumps(self.vpc_pair_list, indent=2))


    def validate_nd_state(self):
        """
        Validates the Nexus Dashboard (ND) state by extracting vPC pair information.

        This method processes the current vPC pair state data stored in self.vpc_pair_state,
        extracts relevant attributes for each vPC pair, and converts them into VpcPairModel
        objects that are appended to the self.have list.

        The method logs its entry point for debugging purposes and creates a standardized
        representation of each vPC pair with the following attributes:
        - peer1SwitchId
        - peer2SwitchId
        - useVirtualPeerLink

        Returns:
            None
        """
        self.class_name = self.__class__.__name__
        method_name = inspect.stack()[0][3]  # pylint: disable=unused-variable

        msg = f"ENTERED: {self.class_name}.{method_name}"
        self.log.debug(msg)

        for vpc_pair in self.vpc_pair_list:
            if not isinstance(vpc_pair, dict):
                raise ValueError(f"vPC pair data is not a dictionary: {vpc_pair}")
            validated_vpc_pair = VpcPairModel.get_model(vpc_pair)
            self.vpc_pairs.append(validated_vpc_pair)
        self.log.debug("Processed vPC pairs: %s", self.vpc_pairs)

    def get_virtual_peer_link_details(self):
        """
        Validates and retrieves virtual peer link details for vPC pairs.
        This method checks if the vPC pairs have virtual peer link enabled for each vPC pair.
        Returns:
            None: Updates the vPC pair configurations with virtual peer link details.
        """
        self.class_name = self.__class__.__name__
        method_name = inspect.stack()[0][3]
        msg = f"ENTERED: {self.class_name}.{method_name}"
        self.log.debug(msg)

        for vpc_pair in self.vpc_pair_list:
            if not isinstance(vpc_pair, dict):
                raise ValueError(f"vPC pair data is not a dictionary: {vpc_pair}")
            self.log.debug("Getting useVirtualPeerLink from vPC pair: %s", vpc_pair)
            peer1_switch_id = vpc_pair.get("peer1SwitchId")
            path = f"{self.recommendation_path}{peer1_switch_id}"
            self.log.debug("Fetching virtual peer link details from path: %s", path)
            self.vpc_pair_recommendation = self.nd.request(path, method=self.verb)
            self.log.debug("vPC pair recommendation response: %s", json.dumps(self.vpc_pair_recommendation, indent=2))
            if not self.vpc_pair_recommendation:
                raise ValueError(f"No vPC pair recommendation found for: {vpc_pair}")
            if len(self.vpc_pair_recommendation) > 1:
                raise ValueError(f"Multiple vPC pair recommendations found for: {vpc_pair}")
            vpc_pair["useVirtualPeerLink"] = self.vpc_pair_recommendation[0].get("useVirtualPeerlink")

class Common:
    """
    Common utility class that provides shared functionality for all state operations in the Cisco ND vPC pair module.

    This class handles the core logic for processing vPC pair configurations across different operational states
    (merged, replaced, deleted, overridden, query) in Ansible tasks. It manages state comparison, parameter
    validation, and payload construction for ND API operations using Pydantic models and utility functions.

    The class leverages utility functions (merge_models, model_payload_with_defaults) to intelligently handle
    vPC pair configuration merging and default value application based on the operation state.

    Attributes:
        modiresult (dict): Dictionary to store operation results including changed state, diffs, API responses and warnings.
        task_params (dict): Parameters provided from the Ansible task.
        state (str): The desired state operation (merged, replaced, deleted, overridden, or query).
        requests (dict): Container for API request requests.
        have (list): List of VpcPairModel objects representing the current state of vPC pairs.
        query (list): List for storing query results.
        validated (list): List of validated configuration items.
        want (list): List of VpcPairModel objects representing the desired state of vPC pairs.

    Methods:
        validate_task_params(): Validates the task parameters and builds the desired state using utility functions.
        vpc_pair_in_have(peer1_switch_id, peer2_switch_id): Checks if a vPC pair with the given pairs exists in current state.
    """

    def __init__(self, task_params, have_state, nd_instance, logger=None):
        self.class_name = self.__class__.__name__
        self.log = logger or logging.getLogger(f"nd.{self.class_name}")

        self.result = dict(changed=False, diff=[], response=[], warnings=[])
        self.task_params = task_params
        self.state = task_params["state"]
        self.requests = {}
        self.nd = nd_instance

        self.have = have_state
        self.query = []
        self.validated = []
        self.want = []

        self.validate_task_params()

        msg = "ENTERED Common(): "
        msg += f"state: {self.state}, "
        self.log.debug(msg)

    def validate_task_params(self):
        """
        Validates and processes task parameters to create vPC pair model objects.

        This method iterates through each vPC pair configuration in the task parameters
        and converts them into VpcPairModel instances based on the current state and
        existing vPC pair configurations. The resulting models are stored in the want list
        for further processing.

        The method uses utility functions to handle different scenarios:
        - For 'merged' state with existing vPC pairs: Uses merge_models() to combine current and desired state
        - For other states or when vPC pairs don't exist: Uses model_payload_with_defaults() for complete configuration

        The method handles the following scenarios:
        - 'merged' state for new and existing vPC pairs
        - 'replaced', 'deleted', 'overridden', and 'query' states

        Returns:
            None: Updates self.want list with processed VpcPairModel objects
        """
        self.class_name = self.__class__.__name__
        method_name = inspect.stack()[0][3]  # pylint: disable=unused-variable

        msg = f"ENTERED: {self.class_name}.{method_name}"
        self.log.debug(msg)

        for vpc_pair in self.task_params.get("config", []):
            have_vpc_pair = self.vpc_pair_in_have(vpc_pair["peer1_switch_id"], vpc_pair["peer2_switch_id"])
            want_vpc_pair = VpcPairModel(**vpc_pair)
            if self.state == "merged" and have_vpc_pair is not None:
                vpc_pair_config_payload = merge_models(have_vpc_pair, want_vpc_pair)
            else:
                # This handles
                #  - Merged when the vPC pair does not yet exist
                #  - Replaced, Deleted, and Query states
                vpc_pair_config_payload = model_payload_with_defaults(want_vpc_pair)

            vpc_pair = VpcPairModel(**vpc_pair_config_payload)
            self.log.debug("Adding vPC pair to want list: %s-%s", vpc_pair.peer1_switch_id, vpc_pair.peer2_switch_id)
            self.log.debug("vPC pair model created: %s", vpc_pair)
            # Add the vPC pair model to the want list
            self.want.append(vpc_pair)

    def vpc_pair_in_have(self, peer1_switch_id, peer2_switch_id):
        """
        Find a vPC pair by pair switch IDs in the current state.

        This method searches through the current state (`self.have`) for a vPC pair
        with the specified pair switch IDs and returns it if found.

        Args:
            peer1_switch_id (str): The peer1 switch ID of the vPC pair to find.
            peer2_switch_id (str): The peer2 switch ID of the vPC pair to find.

        Returns:
            object: The vPC pair object if found, None otherwise.
        """
        self.class_name = self.__class__.__name__
        method_name = inspect.stack()[0][3]  # pylint: disable=unused-variable

        msg = f"ENTERED: {self.class_name}.{method_name} with peer1_switch_id: {peer1_switch_id}, peer2_switch_id: {peer2_switch_id}"
        self.log.debug(msg)

        have_vpc_pair = next((h for h in self.have if h.peer1_switch_id == peer1_switch_id and h.peer2_switch_id == peer2_switch_id), None)
        return have_vpc_pair


class Merged:
    """
    A class that implements the 'merged' state strategy for Cisco ND vPC pair configurations.

    This class compares the desired state ('want') with the current state ('have') of
    vPC pairs and generates the necessary API requests to bring the current state in line
    with the desired state. When using the 'merged' state, existing configurations are
    preserved and only the differences or additions are applied.

    The class calculates differences between configurations using DeepDiff and constructs
    appropriate REST API calls (POST for new vPC pairs, PUT for existing ones) with requests
    that reflect only the changes needed.

    Attributes:
        common (Common): Common utility instance for shared functionality
        verb (str): HTTP verb for the API call (POST or PUT)
        path (str): API endpoint path for the request

    Methods:
        build_request(): Analyzes desired state against current state and builds API requests
        update_payload_merged(have, want): Generates a merged request payload from current and desired states
        _parse_path(path): Parses DeepDiff paths into component parts
        _process_values_changed(diff, updated_payload): Updates changed values in the payload
        _process_dict_items_added(diff, updated_payload, want_dict): Adds new items to the payload
    """

    def __init__(self, task_params, have_state, nd_instance, logger=None, common_util=None):
        self.class_name = self.__class__.__name__
        self.log = logger or logging.getLogger(f"nd.{self.class_name}")

        self.common = common_util or Common(task_params, have_state, nd_instance)
        self.common.have = have_state

        self.verb = ""
        self.path = ""

        self.build_request()

        msg = "ENTERED Merged(): "
        msg += f"state: {self.common.state}, "
        self.log.debug(msg)

    def build_request(self):
        """
        Build API request for creating or updating vPC pairs.

        This method compares the desired vPC pair configurations (want) with the current
        configurations (have) and prepares appropriate requests for API operations.
        For each vPC pair in the desired state:
        - If the vPC pair matches the current state, it is skipped
        - If the vPC pair doesn't exist in the current state, a POST payload is created
        - If the vPC pair exists but differs from desired state, a PUT payload is created

        The method populates self.common.requests with dictionaries containing:
        - verb: HTTP method (POST or PUT)
        - path: API endpoint path
        - payload: The data to be sent to the API

        No parameters are required as it uses instance attributes for processing.

        Returns:
            None: Updates self.common.requests with operation details
        """
        self.class_name = self.__class__.__name__
        method_name = inspect.stack()[0][3]  # pylint: disable=unused-variable

        msg = f"ENTERED: {self.class_name}.{method_name}"
        self.log.debug(msg)

        for vpc_pair in self.common.want:
            want_vpc_pair = vpc_pair
            have_vpc_pair = self.common.vpc_pair_in_have(want_vpc_pair.peer1_switch_id, want_vpc_pair.peer2_switch_id)

            if want_vpc_pair == have_vpc_pair:
                # want_vpc_pair and have_vpc_pair are the same, no action needed
                self.log.debug("vPC pair %s-%s is already in the desired state, skipping.", want_vpc_pair.peer1_switch_id, want_vpc_pair.peer2_switch_id)
                continue

            vpc_pair_key = f"{want_vpc_pair.peer1_switch_id}-{want_vpc_pair.peer2_switch_id}"

            if not have_vpc_pair:
                # If the vPC pair does not exist in the have state, we will create it
                self.log.debug("vPC pair %s-%s does not exist in the current state, creating it.", want_vpc_pair.peer1_switch_id, want_vpc_pair.peer2_switch_id)
                self.path = f"/api/v1/manage/fabrics/{self.common.nd.params.get('fabric')}/vpcPairs"
                self.verb = "POST"
                payload = want_vpc_pair.to_api_payload()
            else:
                # If the vPC pair already exists in the have state, we will update it
                self.log.debug("vPC pair %s-%s exists in the current state, updating it.", want_vpc_pair.peer1_switch_id, want_vpc_pair.peer2_switch_id)
                self.path = f"/api/v1/manage/fabrics/{self.common.nd.params.get('fabric')}/vpcPairs/{want_vpc_pair.peer1_switch_id}/{want_vpc_pair.peer2_switch_id}"
                self.verb = "PUT"
                payload = self.update_payload_merged(have_vpc_pair, want_vpc_pair)

            self.common.requests[vpc_pair_key] = {
                "verb": self.verb,
                "path": self.path,
                "payload": payload,
            }

    def _parse_path(self, path):
        """
        Parse a string path into a list of path segments.

        This method handles two different path format notations:
        1. Dot notation: "root.key1.key2"
        2. Bracket notation: "root['key1']['key2']"

        In both cases, if the path starts with "root", this prefix is removed from the result.

        Args:
            path (str): The path string to parse in either dot or bracket notation.

        Returns:
            list: A list of path segments/keys.

        Examples:
            >>> _parse_path("root.key1.key2")
            ['key1', 'key2']
            >>> _parse_path("root['key1']['key2']")
            ['key1', 'key2']
            >>> _parse_path("key1.key2")
            ['key1', 'key2']
        """
        self.class_name = self.__class__.__name__
        method_name = inspect.stack()[0][3]  # pylint: disable=unused-variable

        msg = f"ENTERED: {self.class_name}.{method_name}"
        self.log.debug(msg)
        # Handle paths like "root.key1.key2"
        if "." in path and "[" not in path:
            parts = path.split(".")
            if parts[0] == "root":
                parts = parts[1:]
            return parts

        # Handle paths like "root['key1']['key2']"
        parts = re.findall(r"'([^']*)'", path)
        return parts

    def _process_values_changed(self, diff, updated_payload):
        """
        Process values that have changed in the diff and update the payload accordingly.

        This method handles updating nested dictionary values based on the diff structure.
        It navigates through the payload using the path provided in the diff and updates
        the corresponding value with the new value from the diff.

        Args:
            diff (dict): Dictionary containing differences, with a 'values_changed' key
                         that maps to changes where keys are paths and values are dicts
                         with 'new_value' keys.
            updated_payload (dict): The payload to be updated with the new values.

        Returns:
            None: This method updates the updated_payload in-place.

        Notes:
            - Requires self._parse_path method to convert path strings to list of keys
            - Logs debug information using self.log
        """
        self.class_name = self.__class__.__name__
        method_name = inspect.stack()[0][3]  # pylint: disable=unused-variable

        msg = f"ENTERED: {self.class_name}.{method_name}"
        self.log.debug(msg)

        if "values_changed" not in diff:
            return

        # Log the values changed for debugging
        self.log.debug("Values changed: %s", diff["values_changed"])

        for path, change in diff["values_changed"].items():
            parts = self._parse_path(path)

            # Navigate to the correct nested dictionary
            current = updated_payload
            for part in parts[:-1]:
                current = current[part]

            # Update the value
            current[parts[-1]] = change["new_value"]

    def _process_dict_items_added(self, diff, updated_payload, want_dict):
        """
        Process dictionary items that have been added according to the diff.

        This method updates the payload by adding items from the 'want' dictionary
        that are identified as newly added in the diff dictionary.

        Args:
            diff (dict): Dictionary containing differences between 'want' and 'have',
                         expected to have a 'dictionary_item_added' key if there are
                         items to add.
            updated_payload (dict): The payload dictionary to update with new items.
            want_dict (dict): The source dictionary containing the desired state with
                              items to be added.

        Returns:
            None: The method modifies the updated_payload dictionary in place.

        Note:
            The method uses _parse_path() to navigate the nested dictionary structure
            and properly place the new items at their correct locations.
        """
        self.class_name = self.__class__.__name__
        method_name = inspect.stack()[0][3]  # pylint: disable=unused-variable

        msg = f"ENTERED: {self.class_name}.{method_name}"
        self.log.debug(msg)

        if "dictionary_item_added" not in diff:
            return

        # Log the dictionary items added for debugging
        self.log.debug("Dictionary items added: %s", diff["dictionary_item_added"])

        for path in diff["dictionary_item_added"]:
            parts = self._parse_path(path)

            # Navigate to the correct nested dictionary
            current = updated_payload
            for i, part in enumerate(parts[:-1]):
                if part not in current:
                    current[part] = {}
                current = current[part]

            # Get the value from want
            value = want_dict
            for part in parts:
                value = value[part]

            # Add the new item
            current[parts[-1]] = value

    def update_payload_merged(self, have, want):
        """
        Calculate the difference between the have and want states and generate an updated payload.

        This method computes what needs to be changed to transform the current state ('have')
        into the desired state ('want'). It uses DeepDiff to identify differences and applies
        a merge strategy, keeping existing values and updating only what's different or new.

        Parameters
        ----------
        have : object
            The current state of the object as a Pydantic model
        want : object
            The desired state of the object as a Pydantic model

        Returns
        -------
        dict
            Updated payload dictionary containing the merged state that reflects
            the differences between 'have' and 'want'

        Notes
        -----
        - Changed values are processed by _process_values_changed
        - New items are added via _process_dict_items_added
        """
        self.class_name = self.__class__.__name__
        method_name = inspect.stack()[0][3]  # pylint: disable=unused-variable

        have = have.model_dump(by_alias=True)
        updated_payload = copy.deepcopy(have)  # Start with the current state

        want = want.model_dump(by_alias=True)

        msg = f"ENTERED: {self.class_name}.{method_name}"
        self.log.debug(msg)

        # Use DeepDiff to calculate the difference
        diff = DeepDiff(have, want, ignore_order=True)

        # If there are no differences, just return the original payload
        if not diff:
            return updated_payload

        # Update changed values and add any new items
        self._process_values_changed(diff, updated_payload)
        self._process_dict_items_added(diff, updated_payload, want)

        return updated_payload


class Replaced:
    """
    A class for handling 'replaced' state operations on Cisco ND vPC pair resources.

    The Replaced class implements the logic for completely replacing existing vPC pair configurations
    with the desired configurations. When a vPC pair doesn't exist, it will be created; when it exists,
    it will be fully replaced with the specified configuration regardless of current settings.

    This differs from 'merged' state which would only update changed values and add new items.

    Parameters
    ----------
    task_params : dict
        The task_params containing the desired state ('want') for the vPC pairs
    have_state : dict
        The current state of vPC pairs in the system

    Attributes
    ----------
    common : Common
        Common utility instance for shared operations
    verb : str
        The HTTP verb (POST or PUT) for the API call
    path : str
        The API endpoint path for the operation

    Methods
    -------
    build_request()
        Processes each vPC pair in the desired state, compares with current state, and builds
        appropriate API requests for creation or replacement
    """

    def __init__(self, task_params, have_state, nd_instance, logger=None, common_util=None):
        self.class_name = self.__class__.__name__
        self.log = logger or logging.getLogger(f"nd.{self.class_name}")

        self.common = common_util or Common(task_params, have_state, nd_instance)
        self.common.have = have_state

        self.verb = ""
        self.path = ""

        self.build_request()

        msg = "ENTERED Replaced(): "
        msg += f"state: {self.common.state}, "
        self.log.debug(msg)

    def build_request(self):
        """
        Build API requests for vPC pair management operations.

        This method processes the desired vPC pair configurations and generates
        appropriate API requests for creating or updating vPC pairs. It compares
        the desired state (want) with the current state (have) and determines
        the necessary actions.

        The method performs the following operations:
        - Iterates through all desired vPC pair configurations
        - Compares each desired vPC pair with its current state
        - Skips vPC pairs that are already in the desired state
        - Creates POST requests for new vPC pairs that don't exist
        - Creates PUT requests for existing vPC pairs that need updates
        - Uses the complete desired configuration for replaced operations

        The generated requests are stored in self.common.requests dictionary
        with the vPC pair key as the key and a dictionary containing the HTTP
        verb, API path, and payload data as the value.

        Note:
            This method implements a "replaced" strategy where the entire
            desired configuration is used, including default values, rather
            than calculating only the differences like in a "merged" strategy.
        """
        self.class_name = self.__class__.__name__
        method_name = inspect.stack()[0][3]  # pylint: disable=unused-variable

        msg = f"ENTERED: {self.class_name}.{method_name}"
        self.log.debug(msg)

        for vpc_pair in self.common.want:
            want_vpc_pair = vpc_pair
            have_vpc_pair = self.common.vpc_pair_in_have(want_vpc_pair.peer1_switch_id, want_vpc_pair.peer2_switch_id)

            if want_vpc_pair == have_vpc_pair:
                # want_vpc_pair and have_vpc_pair are the same, no action needed
                self.log.debug("vPC pair %s-%s is already in the desired state, skipping.", want_vpc_pair.peer1_switch_id, want_vpc_pair.peer2_switch_id)
                continue

            vpc_pair_key = f"{want_vpc_pair.peer1_switch_id}-{want_vpc_pair.peer2_switch_id}"

            if not have_vpc_pair:
                # If the vPC pair does not exist in the have state, we will create it
                self.path = f"/api/v1/manage/fabrics/{self.common.nd.params.get('fabric')}/vpcPairs"
                self.verb = "POST"
            else:
                # If the vPC pair already exists in the have state, we will update it
                self.path = f"/api/v1/manage/fabrics/{self.common.nd.params.get('fabric')}/vpcPairs/{want_vpc_pair.peer1_switch_id}/{want_vpc_pair.peer2_switch_id}"
                self.verb = "PUT"

            # For replaced we just use the want payload "as is" including any default values
            # This is different from merged where we calculate the difference and only update
            # the changed values and add any new items
            payload = want_vpc_pair.to_api_payload()
            self.common.requests[vpc_pair_key] = {
                "verb": self.verb,
                "path": self.path,
                "payload": payload,
            }


class Deleted:
    """
    Handle deletion of vPC pair configurations.

    This class manages the deletion of vPC pairs by comparing the desired state (want)
    with the current state (have) and preparing DELETE operations for vPC pairs that
    exist in both lists.

    Args:
        task_params: The task_params configuration containing the desired state
        have_state: The current state of vPC pairs in the system

    Attributes:
        class_name (str): Name of the current class for logging purposes
        log (logging.Logger): Logger instance for this class
        common (Common): Common utilities and state management
        verb (str): HTTP verb for the operation ("DELETE")
        path (str): API endpoint template for vPC pair deletion
        delete_vpc_pair_keys (list): List of vPC pair keys to be deleted

    The class identifies vPC pairs that exist in both the desired configuration
    and current system state, then prepares the necessary API calls to delete
    those vPC pairs by formatting the deletion path for each vPC pair and storing
    the operation details in the common requests dictionary.
    """

    def __init__(self, task_params, have_state, nd_instance, logger=None, common_util=None):
        self.class_name = self.__class__.__name__
        self.log = logger or logging.getLogger(f"nd.{self.class_name}")

        self.common = common_util or Common(task_params, have_state, nd_instance)
        self.common.have = have_state
        self.verb = "DELETE"
        self.path = "/api/v1/manage/fabrics/{fabric}/vpcPairs/{peer1_switch_id}/{peer2_switch_id}"

        # Create a list of vPC pair keys to be deleted that are in both self.common.want and self.have
        self.delete_vpc_pair_keys = []
        for want_vpc_pair in self.common.want:
            have_vpc_pair = self.common.vpc_pair_in_have(want_vpc_pair.peer1_switch_id, want_vpc_pair.peer2_switch_id)
            if have_vpc_pair:
                vpc_pair_key = f"{want_vpc_pair.peer1_switch_id}-{want_vpc_pair.peer2_switch_id}"
                self.delete_vpc_pair_keys.append((vpc_pair_key, want_vpc_pair.peer1_switch_id, want_vpc_pair.peer2_switch_id))

        for vpc_pair_key, peer1_switch_id, peer2_switch_id in self.delete_vpc_pair_keys:
            # Create a path for each vPC pair to be deleted
            self.common.requests[vpc_pair_key] = {
                "verb": self.verb,
                "path": self.path.format(fabric=self.common.nd.params.get('fabric'), peer1_switch_id=peer1_switch_id, peer2_switch_id=peer2_switch_id),
                "payload": "",
            }

        msg = "ENTERED Deleted(): "
        msg += f"state: {self.common.state}, "
        self.log.debug(msg)


class Overridden:
    """
    Handles the 'overridden' state for vPC pair management operations.

    This class manages the overridden state by deleting vPC pairs that exist in the current
    state but are not present in the desired state, and then creating or replacing vPC pairs
    that are specified in the desired state.

    The overridden operation is a combination of:
    1. Deleting vPC pairs that exist in 'have' but not in 'want'
    2. Creating or replacing vPC pairs specified in 'want'

    Args:
        task_params: The Ansible task_params context containing configuration data
        have_state: Current state of vPC pairs in the system
        logger (optional): Logger instance for debugging. Defaults to None
        common_util (optional): Common utility instance. Defaults to None
        replaced_task (optional): Replaced task instance. Defaults to None

    Attributes:
        class_name (str): Name of the current class
        log: Logger instance for debugging operations
        common: Common utility instance for shared operations
        verb (str): HTTP verb used for delete operations ('DELETE')
        path (str): API endpoint template for vPC pair deletion
        delete_vpc_pair_keys (list): List of vPC pair keys to be deleted
    """

    def __init__(self, task_params, have_state, nd_instance, logger=None, common_util=None, replaced_task=None):
        self.class_name = self.__class__.__name__
        self.log = logger or logging.getLogger(f"nd.{self.class_name}")

        self.common = common_util or Common(task_params, have_state, nd_instance)
        self.common.have = have_state
        self.verb = "DELETE"
        self.path = "/api/v1/manage/fabrics/{fabric}/vpcPairs/{peer1_switch_id}/{peer2_switch_id}"

        # Use the Replaced() to create new vPC pairs or replace existing ones
        replaced_task = Replaced(task_params, have_state, nd_instance)

        # Create a list of vPC pair keys to be deleted that are not in self.common.want but are in self.have
        self.delete_vpc_pair_keys = []
        for have_vpc_pair in self.common.have:
            # Check if this have_vpc_pair exists in the want list
            want_vpc_pair = next((w for w in self.common.want if w.peer1_switch_id == have_vpc_pair.peer1_switch_id and w.peer2_switch_id == have_vpc_pair.peer2_switch_id), None)
            if not want_vpc_pair:
                vpc_pair_key = f"{have_vpc_pair.peer1_switch_id}-{have_vpc_pair.peer2_switch_id}"
                self.delete_vpc_pair_keys.append((vpc_pair_key, have_vpc_pair.peer1_switch_id, have_vpc_pair.peer2_switch_id))

        for vpc_pair_key, peer1_switch_id, peer2_switch_id in self.delete_vpc_pair_keys:
            # Create a path for each vPC pair to be deleted
            self.common.requests[vpc_pair_key] = {
                "verb": self.verb,
                "path": self.path.format(fabric=self.common.nd.params.get('fabric'), peer1_switch_id=peer1_switch_id, peer2_switch_id=peer2_switch_id),
                "payload": "",
            }

        # Merge replace_task.common.requests into self.common.requests
        for vpc_pair_key, request_data in replaced_task.common.requests.items():
            self.common.requests[vpc_pair_key] = request_data

        msg = "ENTERED Overridden(): "
        msg += f"state: {self.common.state}, "
        self.log.debug(msg)


class Query:
    """
    Query class for managing vPC pair queries in Cisco ND.

    This class handles querying operations for vPC pair management in the Cisco Nexus Dashboard.
    It provides functionality to retrieve and return vPC pair state information.

    Args:
        task_params: The Ansible task_params context containing configuration parameters
        have_state: The current state of the vPC pairs being queried

    Attributes:
        class_name (str): The name of the current class
        log (logging.Logger): Logger instance for the Query class
        common (Common): Common utility instance for shared operations
        have: The current have state of the vPC pairs

    Note:
        This class is part of the Cisco ND Ansible collection for vPC pair management
        operations and follows the standard query pattern for state retrieval.
    """

    def __init__(self, task_params, have_state, nd_instance, logger=None, common_util=None):
        self.class_name = self.__class__.__name__
        self.log = logger or logging.getLogger(f"nd.{self.class_name}")
        self.common = common_util or Common(task_params, have_state, nd_instance)
        self.have = have_state

        msg = "ENTERED Query(): "
        msg += f"state: {self.common.state}, "
        self.log.debug(msg)
    
    def get_query_results(self):
        """
        Retrieve the current state of vPC pairs.

        This method collects the current state of vPC pairs from the have state
        and prepares it for output in the query result format.

        Returns:
            list: A list of vPC pair configurations in the desired format.
        """
        self.class_name = self.__class__.__name__
        method_name = inspect.stack()[0][3]  # pylint: disable=unused-variable
        msg = f"ENTERED: {self.class_name}.{method_name}"
        self.log.debug(msg)


def main():
    argument_spec = {}
    argument_spec.update(
        state=dict(
            type="str",
            default="merged",
            choices=["merged", "replaced", "deleted", "overridden", "query"],
        ),
        fabric=dict(required=True, type="str"),
        config=dict(required=False, type="list", elements="dict"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    if sys.version_info < (3, 9):
        module.fail_json(msg="Python version 3.9 or higher is required for this module.")

    if not HAS_DEEPDIFF:
        module.fail_json(msg=missing_required_lib("deepdiff"), exception=DEEPDIFF_IMPORT_ERROR)

    # Logging setup
    try:
        log = Log()
        log.commit()
        mainlog = logging.getLogger("nd.main")
    except ValueError as error:
        module.fail_json(str(error))

    mainlog.info("---------------------------------------------")
    mainlog.info("Starting cisco.nd.nd_manage_vpc_pairs module")
    mainlog.info("---------------------------------------------\n")
    nd = NDModule(module)
    task_params = nd.params
    mainlog.debug("Task parameters: %s", task_params)
    inventory = UpdateInventory(nd)
    inventory.refresh()
    
    want = GetWant(inventory, task_params)
    want.validate_task_params()

    have = GetHave(nd, inventory)
    have.refresh()
    have.validate_nd_state()
    mainlog.debug("Haves: %s", have.vpc_pairs)
    mainlog.debug("Wants: %s", want.vpc_pairs)
    mainlog.debug(want.vpc_pairs[0] == have.vpc_pairs[0])
    # try:
    #     task = None
    #     if task_params.get("state") == "merged":
    #         task = Merged(task_params, have.vpc_pairs, nd)
    #     elif task_params.get("state") == "replaced":
    #         task = Replaced(task_params, have.vpc_pairs, nd)
    #     elif task_params.get("state") == "deleted":
    #         task = Deleted(task_params, have.vpc_pairs, nd)
    #     elif task_params.get("state") == "overridden":
    #         task = Overridden(task_params, have.vpc_pairs, nd)
    #     elif task_params.get("state") == "query":
    #         task = Query(task_params, have.vpc_pairs, nd)
    #     if task is None:
    #         module.fail_json(f"Invalid state: {task_params['state']}")
    # except ValueError as error:
    #     module.fail_json(f"{error}")

    # # If the task is a query, we will just return the have state
    # if isinstance(task, Query):
    #     for vpc_pair in vpc_pairs.have:
    #         task.common.query.append(vpc_pair.model_dump(by_alias=True))
    #     task.common.result["query"] = task.common.query
    #     task.common.result["changed"] = False
    #     module.exit_json(**task.common.result)

    # # Process all the requests from task.common.requests
    # # Sample entry:
    # #   {'FDO23040Q85-FDO23040Q86': {'verb': 'DELETE', 'path': '/api/v1/manage/vpc-pairs/FDO23040Q85/FDO23040Q86', 'payload': ''}}
    # if task.common.requests:
    #     for vpc_pair_key, request_data in task.common.requests.items():
    #         verb = request_data["verb"]
    #         path = request_data["path"]
    #         payload = request_data["payload"]

    #         # Pretty-print the payload for easier log reading
    #         pretty_payload = json.dumps(payload, indent=2, sort_keys=True)
    #         mainlog.info("Calling nd.request with path: %s, verb: %s, and payload:\n%s", path, verb, pretty_payload)
    #         # Make the API request
    #         response = nd.request(path, method=verb, data=payload if payload else None)
    #         task.common.result["response"].append(response)
    #         task.common.result["changed"] = True
    # else:
    #     mainlog.info("No requests to process")

    # module.exit_json(**task.common.result)


if __name__ == "__main__":
    main()
    
