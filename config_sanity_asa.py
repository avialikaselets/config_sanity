#!/usr/bin/python3

import pprint

access_lists = {}
used_access_lists = {}
unused_access_lists = set()

objects = {}
used_objects = {}
unused_objects = set()

object_groups = {}
used_object_groups = {}
unused_object_groups = set()

# Incoming configuration file separated in lines
input_config = []

# Configuration file after all sanity items are removed
sanitized_config = []

def sanitize_acls(line_num, input_line_split):
	if not input_line_split[1] in access_lists:
		access_lists.setdefault(input_line_split[1], [])
	access_lists[input_line_split[1]].append(" ".join(input_line_split[2:]).strip())
	return line_num + 1

def sanitize_objects(line_num, input_line_split):
	if not (input_line_split[2].strip(), input_line_split[1]) in objects:
		objects.setdefault((input_line_split[2].strip(), input_line_split[1]), [])
	line_num += 1
	while input_config[line_num].startswith(" "):
		objects[(input_line_split[2].strip(), input_line_split[1])].append(input_config[line_num].strip())
		line_num += 1
	return line_num

def sanitize_object_groups(line_num, input_line_split):
	if not (input_line_split[2].strip(), input_line_split[1]) in object_groups:
		object_groups.setdefault((input_line_split[2].strip(), input_line_split[1]), [])
	line_num += 1
	while input_config[line_num].startswith(" "):
		object_groups[(input_line_split[2].strip(), input_line_split[1])].append(input_config[line_num].strip())
		line_num += 1
	return line_num

def sort_access_lists(access_lists):
	access_list_used = False
	for access_list in sorted(access_lists.keys()):
		for line in sanitized_config:
			if access_list in line:
				used_access_lists.setdefault(access_list, access_lists[access_list])
				access_list_used = True
				break
		if not access_list_used:
			unused_access_lists.add(access_list)
		access_list_used = False				
	return used_access_lists, unused_access_lists

def sort_object_groups(object_groups):
	object_group_used = False
	for object_group in sorted(object_groups.keys()):
		for line in sanitized_config:
			if object_group[0] in line:
				used_object_groups.setdefault(object_group, object_groups[object_group])
				object_group_used = True
				break
		if not object_group_used:
			unused_object_groups.add(object_group)
		object_group_used = False

	used_access_lists_lines = []
	for entry in used_access_lists.values():
		for line in entry:
			used_access_lists_lines.append(line)

	for object_group in sorted(unused_object_groups):
		for line in used_access_lists_lines:
			if object_group[0] in line:
				used_object_groups.setdefault(object_group, object_groups[object_group])
				unused_object_groups.remove(object_group)
				break

	used_object_groups_lines = []
	for entry in used_object_groups.values():
		for line in entry:
			used_object_groups_lines.append(line)

	for object_group in sorted(unused_object_groups):
		for line in used_object_groups_lines:
			if object_group[0] in line:
				used_object_groups.setdefault(object_group, object_groups[object_group])
				unused_object_groups.remove(object_group)
				break

	return used_object_groups, unused_object_groups

def sort_objects(objects):
	object_used = False
	for _object in sorted(objects.keys()):
		for line in sanitized_config:
			if _object[0] in line:
				used_objects.setdefault(_object, objects[_object])
				object_used = True
				break
		if not object_used:
			unused_objects.add(_object)
		object_used = False

	used_access_lists_lines = []
	for entry in used_access_lists.values():
		for line in entry:
			used_access_lists_lines.append(line)

	for _object in sorted(unused_objects):
		for line in used_access_lists_lines:
			if _object[0] in line:
				used_objects.setdefault(_object, objects[_object])
				unused_objects.remove(_object)
				break

	used_object_groups_lines = []
	for entry in used_object_groups.values():
		for line in entry:
			used_object_groups_lines.append(line)

	for _object in sorted(unused_objects):
		for line in used_object_groups_lines:
			if _object[0] in line:
				used_objects.setdefault(_object, objects[_object])
				unused_objects.remove(_object)
				break

	used_objects_lines = []
	for entry in used_objects.values():
		for line in entry:
			used_objects_lines.append(line)

	for _object in sorted(unused_objects):
		for line in used_objects_lines:
			if _object[0] in line:
				used_objects.setdefault(_object, objects[_object])
				unused_objects.remove(_object)
				break

	return used_objects, unused_objects
	

# List which configuration items we want to check if they are needed and their
# check functions
sanity_items = {"access-list": sanitize_acls,
			    "object": sanitize_objects,
			    "object-group": sanitize_object_groups
			    }


# route-map <NAME>
# access-list <NAME> -- всретится только в sanitized конфиге
# prefix-list <NAME>
# object network <NAME> -- встретися в sanitized конфиге, ACL или object-group'е
# object service <NAME> -- встретися в sanitized конфиге, ACL или object-group'е
# object-group network <NAME>  -- встретися в sanitized конфиге, ACL или object-group'е
# object-group service <NAME>  -- встретися в sanitized конфиге, ACL или object-group'е
# object-group protocol <NAME>  -- встретися в sanitized конфиге, ACL или object-group'е


# ^object service.+$(\n .+)+

with open('5.12.2020_2-10-26_AM_Startup.config', 'r') as input_file:
	input_config = input_file.readlines()

line_num = 0

while line_num < len(input_config):
	input_line_split = input_config[line_num].split(" ")
	if input_line_split[0] in sanity_items:
		line_num = sanity_items.get(input_line_split[0])(line_num, input_line_split)
	else:
		sanitized_config.append(input_config[line_num])
		line_num += 1

line_num = 0

# print(find_unused_access_lists())

# pprint.pprint(object_groups)

with open('sanitized_config.txt', 'w') as output_file:
	for line in sanitized_config:
		output_file.write(line)

with open('sanitizing.log', 'w') as log_file:
	log_file.write("Checking Access-lists:\n")
	used_access_lists, unused_access_lists = sort_access_lists(access_lists)
	used_object_groups, unused_object_groups = sort_object_groups(object_groups)
	used_objects, unused_objects = sort_objects(objects)
	'''
	for access_list_name in sorted(access_lists.keys()):
		line = access_list_used(access_list_name)
		log_file.write(access_list_name + " is used in line ")
		if line != None:
			log_file.write('"' + line + '"' + "\n")
		else:
			log_file.write("NO LINE!" + "\n")
	log_file.write("\n\n")
	'''	
	log_file.write("Checking Object-groups:\n")
	log_file.write("Looking through sanitized config:\n")
	'''
	for object_group in sorted(object_groups.keys()):
		line = object_group_used(object_group[0])
		log_file.write(object_group[0] + " is used in line ")
		if line != None:
			log_file.write('"' + line + '"' + "\n")
		else:
			log_file.write("NO LINE!" + "\n")
	'''		

pprint.pprint(unused_access_lists)
pprint.pprint(unused_object_groups)
pprint.pprint(unused_objects)
