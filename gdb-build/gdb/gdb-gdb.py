# Copyright (C) 2009-2025 Free Software Foundation, Inc.
#
# This file is part of GDB.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os.path

import gdb


class TypeFlag:
    """A class that allows us to store a flag name, its short name,
    and its value.

    In the GDB sources, struct type has a component called instance_flags
    in which the value is the addition of various flags.  These flags are
    defined by the enumerates type_instance_flag_value.  This class helps us
    recreate a list with all these flags that is easy to manipulate and sort.
    Because all flag names start with TYPE_INSTANCE_FLAG_, a short_name
    attribute is provided that strips this prefix.

    ATTRIBUTES
      name:  The enumeration name (eg: "TYPE_INSTANCE_FLAG_CONST").
      value: The associated value.
      short_name: The enumeration name, with the suffix stripped.
    """

    def __init__(self, name, value):
        self.name = name
        self.value = value
        self.short_name = name.replace("TYPE_INSTANCE_FLAG_", "")

    def __lt__(self, other):
        """Sort by value order."""
        return self.value < other.value


# A list of all existing TYPE_INSTANCE_FLAGS_* enumerations,
# stored as TypeFlags objects.  Lazy-initialized.
TYPE_FLAGS = None


class TypeFlagsPrinter:
    """A class that prints a decoded form of an instance_flags value.

    This class uses a global named TYPE_FLAGS, which is a list of
    all defined TypeFlag values.  Using a global allows us to compute
    this list only once.

    This class relies on a couple of enumeration types being defined.
    If not, then printing of the instance_flag is going to be degraded,
    but it's not a fatal error.
    """

    def __init__(self, val):
        self.val = val

    def __str__(self):
        global TYPE_FLAGS
        if TYPE_FLAGS is None:
            self.init_TYPE_FLAGS()
        if not self.val:
            return "0"
        if TYPE_FLAGS:
            flag_list = [
                flag.short_name for flag in TYPE_FLAGS if self.val & flag.value
            ]
        else:
            flag_list = ["???"]
        return "0x%x [%s]" % (self.val, "|".join(flag_list))

    def init_TYPE_FLAGS(self):
        """Initialize the TYPE_FLAGS global as a list of TypeFlag objects.
        This operation requires the search of a couple of enumeration types.
        If not found, a warning is printed on stdout, and TYPE_FLAGS is
        set to the empty list.

        The resulting list is sorted by increasing value, to facilitate
        printing of the list of flags used in an instance_flags value.
        """
        global TYPE_FLAGS
        TYPE_FLAGS = []
        try:
            iflags = gdb.lookup_type("enum type_instance_flag_value")
        except:
            print("Warning: Cannot find enum type_instance_flag_value type.")
            print("         `struct type' pretty-printer will be degraded")
            return
        TYPE_FLAGS = [TypeFlag(field.name, field.enumval) for field in iflags.fields()]
        TYPE_FLAGS.sort()


class StructTypePrettyPrinter:
    """Pretty-print an object of type struct type"""

    def __init__(self, val):
        self.val = val

    def to_string(self):
        fields = []
        fields.append("pointer_type = %s" % self.val["pointer_type"])
        fields.append("reference_type = %s" % self.val["reference_type"])
        fields.append("chain = %s" % self.val["reference_type"])
        fields.append(
            "instance_flags = %s" % TypeFlagsPrinter(self.val["m_instance_flags"])
        )
        fields.append("length = %d" % self.val["m_length"])
        fields.append("main_type = %s" % self.val["main_type"])
        return "\n{" + ",\n ".join(fields) + "}"


class StructMainTypePrettyPrinter:
    """Pretty-print an object of type main_type"""

    def __init__(self, val):
        self.val = val

    def flags_to_string(self):
        """struct main_type contains a series of components that
        are one-bit ints whose name start with "flag_".  For instance:
        flag_unsigned, flag_stub, etc.  In essence, these components are
        really boolean flags, and this method prints a short synthetic
        version of the value of all these flags.  For instance, if
        flag_unsigned and flag_static are the only components set to 1,
        this function will return "unsigned|static".
        """
        fields = [
            field.name.replace("flag_", "")
            for field in self.val.type.fields()
            if field.name.startswith("flag_") and self.val[field.name]
        ]
        return "|".join(fields)

    def owner_to_string(self):
        """Return an image of component "owner"."""
        if self.val["m_flag_objfile_owned"] != 0:
            return "%s (objfile)" % self.val["m_owner"]["objfile"]
        else:
            return "%s (gdbarch)" % self.val["m_owner"]["gdbarch"]

    def struct_field_location_img(self, field_val):
        """Return an image of the loc component inside the given field
        gdb.Value.
        """
        loc_val = field_val["m_loc"]
        loc_kind = str(field_val["m_loc_kind"])
        if loc_kind == "FIELD_LOC_KIND_BITPOS":
            return "bitpos = %d" % loc_val["bitpos"]
        elif loc_kind == "FIELD_LOC_KIND_ENUMVAL":
            return "enumval = %d" % loc_val["enumval"]
        elif loc_kind == "FIELD_LOC_KIND_PHYSADDR":
            return "physaddr = 0x%x" % loc_val["physaddr"]
        elif loc_kind == "FIELD_LOC_KIND_PHYSNAME":
            return "physname = %s" % loc_val["physname"]
        elif loc_kind == "FIELD_LOC_KIND_DWARF_BLOCK_ADDR":
            return "dwarf_block_addr = %s" % loc_val["dwarf_block"]
        elif loc_kind == "FIELD_LOC_KIND_DWARF_BLOCK_BITPOS":
            return "dwarf_block_bitpos = %s" % loc_val["dwarf_block"]
        else:
            return "m_loc = ??? (unsupported m_loc_kind value)"

    def struct_field_img(self, fieldno):
        """Return an image of the main_type field number FIELDNO."""
        f = self.val["flds_bnds"]["fields"][fieldno]
        label = "flds_bnds.fields[%d]:" % fieldno
        if f["m_artificial"]:
            label += " (artificial)"
        fields = []
        fields.append("m_name = %s" % f["m_name"])
        fields.append("m_type = %s" % f["m_type"])
        fields.append("m_loc_kind = %s" % f["m_loc_kind"])
        fields.append("bitsize = %d" % f["m_bitsize"])
        fields.append(self.struct_field_location_img(f))
        return label + "\n" + "  {" + ",\n   ".join(fields) + "}"

    def bound_img(self, bound_name):
        """Return an image of the given main_type's bound."""
        bounds = self.val["flds_bnds"]["bounds"].dereference()
        b = bounds[bound_name]
        bnd_kind = str(b["m_kind"])
        if bnd_kind == "PROP_CONST":
            return str(b["m_data"]["const_val"])
        elif bnd_kind == "PROP_UNDEFINED":
            return "(undefined)"
        else:
            info = [bnd_kind]
            if bound_name == "high" and bounds["flag_upper_bound_is_count"]:
                info.append("upper_bound_is_count")
            return "{} ({})".format(str(b["m_data"]["baton"]), ",".join(info))

    def bounds_img(self):
        """Return an image of the main_type bounds."""
        b = self.val["flds_bnds"]["bounds"].dereference()
        low = self.bound_img("low")
        high = self.bound_img("high")

        img = "flds_bnds.bounds = {%s, %s}" % (low, high)
        if b["flag_bound_evaluated"]:
            img += " [evaluated]"
        return img

    def type_specific_img(self):
        """Return a string image of the main_type type_specific union.
        Only the relevant component of that union is printed (based on
        the value of the type_specific_kind field.
        """
        type_specific_kind = str(self.val["type_specific_field"])
        type_specific = self.val["type_specific"]
        if type_specific_kind == "TYPE_SPECIFIC_NONE":
            img = "type_specific_field = %s" % type_specific_kind
        elif type_specific_kind == "TYPE_SPECIFIC_CPLUS_STUFF":
            img = "cplus_stuff = %s" % type_specific["cplus_stuff"]
        elif type_specific_kind == "TYPE_SPECIFIC_GNAT_STUFF":
            img = (
                "gnat_stuff = {descriptive_type = %s}"
                % type_specific["gnat_stuff"]["descriptive_type"]
            )
        elif type_specific_kind == "TYPE_SPECIFIC_FLOATFORMAT":
            img = "floatformat[0..1] = %s" % type_specific["floatformat"]
        elif type_specific_kind == "TYPE_SPECIFIC_FUNC":
            img = (
                "calling_convention = %d"
                % type_specific["func_stuff"]["calling_convention"]
            )
            # tail_call_list is not printed.
        elif type_specific_kind == "TYPE_SPECIFIC_SELF_TYPE":
            img = "self_type = %s" % type_specific["self_type"]
        elif type_specific_kind == "TYPE_SPECIFIC_FIXED_POINT":
            # The scaling factor is an opaque structure, so we cannot
            # decode its value from Python (not without insider knowledge).
            img = (
                "scaling_factor: <opaque> (call __gmpz_dump with "
                " _mp_num and _mp_den fields if needed)"
            )
        elif type_specific_kind == "TYPE_SPECIFIC_INT":
            img = "int_stuff = { bit_size = %d, bit_offset = %d }" % (
                type_specific["int_stuff"]["bit_size"],
                type_specific["int_stuff"]["bit_offset"],
            )
        else:
            img = (
                "type_specific = ??? (unknown type_specific_kind: %s)"
                % type_specific_kind
            )
        return img

    def to_string(self):
        """Return a pretty-printed image of our main_type."""
        fields = []
        fields.append("name = %s" % self.val["name"])
        fields.append("code = %s" % self.val["code"])
        fields.append("flags = [%s]" % self.flags_to_string())
        fields.append("owner = %s" % self.owner_to_string())
        fields.append("target_type = %s" % self.val["m_target_type"])
        if self.val["m_nfields"] > 0:
            for fieldno in range(self.val["m_nfields"]):
                fields.append(self.struct_field_img(fieldno))
        if self.val["code"] == gdb.TYPE_CODE_RANGE:
            fields.append(self.bounds_img())
        fields.append(self.type_specific_img())

        return "\n{" + ",\n ".join(fields) + "}"


class CoreAddrPrettyPrinter:
    """Print CORE_ADDR values as hex."""

    def __init__(self, val):
        self._val = val

    def to_string(self):
        return hex(int(self._val))


class IntrusiveListPrinter:
    """Print a struct intrusive_list."""

    def __init__(self, val):
        self._val = val

        # Type of linked items.
        self._item_type = self._val.type.template_argument(0)
        self._node_ptr_type = gdb.lookup_type(
            "intrusive_list_node<{}>".format(self._item_type.tag)
        ).pointer()

        # Type of value -> node converter.
        self._conv_type = self._val.type.template_argument(1)

        if self._uses_member_node():
            # The second template argument of intrusive_member_node is a member
            # pointer value.  Its value is the offset of the node member in the
            # enclosing type.
            member_node_ptr = self._conv_type.template_argument(1)
            member_node_ptr = member_node_ptr.cast(gdb.lookup_type("int"))
            self._member_node_offset = int(member_node_ptr)

            # This is only needed in _as_node_ptr if using a member node.  Look it
            # up here so we only do it once.
            self._char_ptr_type = gdb.lookup_type("char").pointer()

    def display_hint(self):
        return "array"

    def _uses_member_node(self):
        """Return True if the list items use a node as a member, False if
        they use a node as a base class.
        """

        if self._conv_type.name.startswith("intrusive_member_node<"):
            return True
        elif self._conv_type.name.startswith("intrusive_base_node<"):
            return False
        else:
            raise RuntimeError(
                "Unexpected intrusive_list value -> node converter type: {}".format(
                    self._conv_type.name
                )
            )

    def to_string(self):
        s = "intrusive list of {}".format(self._item_type)

        if self._uses_member_node():
            node_member = self._conv_type.template_argument(1)
            s += ", linked through {}".format(node_member)

        return s

    def _as_node_ptr(self, elem_ptr):
        """Given ELEM_PTR, a pointer to a list element, return a pointer to the
        corresponding intrusive_list_node.
        """

        assert elem_ptr.type.strip_typedefs().code == gdb.TYPE_CODE_PTR

        if self._uses_member_node():
            # Node as a member: add the member node offset from to the element's
            # address to get the member node's address.
            elem_char_ptr = elem_ptr.cast(self._char_ptr_type)
            node_char_ptr = elem_char_ptr + self._member_node_offset
            return node_char_ptr.cast(self._node_ptr_type)
        else:
            # Node as a base: just casting from node pointer to item pointer
            # will adjust the pointer value.
            return elem_ptr.cast(self._node_ptr_type)

    def _children_generator(self):
        """Generator that yields one tuple per list item."""

        elem_ptr = self._val["m_front"]
        idx = 0
        while elem_ptr != 0:
            yield (str(idx), elem_ptr.dereference())
            node_ptr = self._as_node_ptr(elem_ptr)
            elem_ptr = node_ptr["next"]
            idx += 1

    def children(self):
        return self._children_generator()


class HtabPrinter:
    """Pretty-printer for htab_t hash tables."""

    def __init__(self, val):
        self._val = val

    def display_hint(self):
        return "array"

    def to_string(self):
        n = int(self._val["n_elements"]) - int(self._val["n_deleted"])
        return "htab_t with {} elements".format(n)

    def children(self):
        size = int(self._val["size"])
        entries = self._val["entries"]

        child_i = 0
        for entries_i in range(size):
            entry = entries[entries_i]
            # 0 (NULL pointer) means there's nothing, 1 (HTAB_DELETED_ENTRY)
            # means there was something, but is now deleted.
            if int(entry) in (0, 1):
                continue

            yield (str(child_i), entry)
            child_i += 1


def type_lookup_function(val):
    """A routine that returns the correct pretty printer for VAL
    if appropriate.  Returns None otherwise.
    """
    tag = val.type.tag
    name = val.type.name
    if tag == "type":
        return StructTypePrettyPrinter(val)
    elif tag == "main_type":
        return StructMainTypePrettyPrinter(val)
    elif name == "CORE_ADDR":
        return CoreAddrPrettyPrinter(val)
    elif tag is not None and tag.startswith("intrusive_list<"):
        return IntrusiveListPrinter(val)
    elif name == "htab_t":
        return HtabPrinter(val)
    return None


def register_pretty_printer(objfile):
    """A routine to register a pretty-printer against the given OBJFILE."""
    objfile.pretty_printers.append(type_lookup_function)


if __name__ == "__main__":
    if gdb.current_objfile() is not None:
        # This is the case where this script is being "auto-loaded"
        # for a given objfile.  Register the pretty-printer for that
        # objfile.
        register_pretty_printer(gdb.current_objfile())
    else:
        # We need to locate the objfile corresponding to the GDB
        # executable, and register the pretty-printer for that objfile.
        # FIXME: The condition used to match the objfile is too simplistic
        # and will not work on Windows.
        for objfile in gdb.objfiles():
            if os.path.basename(objfile.filename) == "gdb":
                objfile.pretty_printers.append(type_lookup_function)
