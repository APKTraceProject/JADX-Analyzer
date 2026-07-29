import xml.etree.ElementTree as ET
from pathlib import Path


ANDROID_NAMESPACE = (
    "http://schemas.android.com/"
    "apk/res/android"
)


def _find_manifest(
    output_dir: Path
) -> Path:
    """Find AndroidManifest.xml."""

    possible_paths = [
        output_dir
        / "resources"
        / "AndroidManifest.xml",

        output_dir
        / "AndroidManifest.xml"
    ]

    for manifest_path in possible_paths:

        if manifest_path.is_file():
            return manifest_path

    manifests = list(
        output_dir.rglob(
            "AndroidManifest.xml"
        )
    )

    if manifests:
        return manifests[0]

    raise FileNotFoundError(
        "AndroidManifest.xml was not "
        "found in JADX output."
    )


def _get_android_attribute(
    element,
    attribute_name: str
):
    """Get an Android XML attribute."""

    possible_names = [
        (
            f"{{{ANDROID_NAMESPACE}}}"
            f"{attribute_name}"
        ),

        f"android:{attribute_name}",

        attribute_name
    ]

    for name in possible_names:

        value = element.get(name)

        if value is not None:
            return value

    return None


def _normalize_component_name(
    component_name,
    package_name
):
    """Convert a component name to its full name."""

    if component_name is None:
        return None

    component_name = (
        component_name.strip()
    )

    if not component_name:
        return None

    if component_name.startswith(
        "."
    ):

        if package_name:

            return (
                f"{package_name}"
                f"{component_name}"
            )

        return component_name

    if "." not in component_name:

        if package_name:

            return (
                f"{package_name}."
                f"{component_name}"
            )

    return component_name


def _convert_boolean(
    value
):
    """Convert an Android boolean value."""

    if value is None:
        return None

    value = (
        value.strip()
        .lower()
    )

    if value == "true":
        return True

    if value == "false":
        return False

    return None


def _get_intent_filters(
    component
) -> list:
    """Extract intent filters from a component."""

    intent_filters = []

    for intent_filter in component.findall(
        "intent-filter"
    ):

        actions = []

        categories = []

        data_items = []

        for action in intent_filter.findall(
            "action"
        ):

            action_name = (
                _get_android_attribute(
                    action,
                    "name"
                )
            )

            if action_name is not None:

                actions.append(
                    action_name
                )

        for category in intent_filter.findall(
            "category"
        ):

            category_name = (
                _get_android_attribute(
                    category,
                    "name"
                )
            )

            if category_name is not None:

                categories.append(
                    category_name
                )

        for data in intent_filter.findall(
            "data"
        ):

            data_item = {}

            attribute_names = [
                "scheme",
                "host",
                "port",
                "path",
                "pathPrefix",
                "pathPattern",
                "mimeType"
            ]

            for attribute_name in attribute_names:

                value = (
                    _get_android_attribute(
                        data,
                        attribute_name
                    )
                )

                if value is not None:

                    data_item[
                        attribute_name
                    ] = value

            if data_item:

                data_items.append(
                    data_item
                )

        intent_filters.append(
            {
                "actions": sorted(
                    set(actions)
                ),

                "categories": sorted(
                    set(categories)
                ),

                "data": data_items
            }
        )

    return intent_filters


def _get_component_exported(
    component,
    intent_filters
):
    """Determine the component exported state."""

    exported_value = (
        _get_android_attribute(
            component,
            "exported"
        )
    )

    explicit_exported = (
        _convert_boolean(
            exported_value
        )
    )

    if explicit_exported is not None:

        return {
            "exported": explicit_exported,
            "exported_source": "explicit"
        }

    inferred_exported = (
        len(intent_filters) > 0
    )

    return {
        "exported": inferred_exported,
        "exported_source": "inferred_from_intent_filter"
    }


def _extract_component(
    component,
    component_type,
    package_name
) -> dict:
    """Extract information from one Android component."""

    component_name = (
        _normalize_component_name(
            _get_android_attribute(
                component,
                "name"
            ),
            package_name
        )
    )

    intent_filters = (
        _get_intent_filters(
            component
        )
    )

    exported_info = (
        _get_component_exported(
            component,
            intent_filters
        )
    )

    component_data = {
        "name": component_name,

        "type": component_type,

        "exported": (
            exported_info[
                "exported"
            ]
        ),

        "exported_source": (
            exported_info[
                "exported_source"
            ]
        ),

        "permission": (
            _get_android_attribute(
                component,
                "permission"
            )
        ),

        "enabled": (
            _convert_boolean(
                _get_android_attribute(
                    component,
                    "enabled"
                )
            )
        ),

        "process": (
            _get_android_attribute(
                component,
                "process"
            )
        ),

        "intent_filter_count": (
            len(intent_filters)
        ),

        "intent_filters": (
            intent_filters
        )
    }

    if component_type == "provider":

        component_data[
            "authorities"
        ] = (
            _get_android_attribute(
                component,
                "authorities"
            )
        )

        component_data[
            "grant_uri_permissions"
        ] = (
            _convert_boolean(
                _get_android_attribute(
                    component,
                    "grantUriPermissions"
                )
            )
        )

        component_data[
            "read_permission"
        ] = (
            _get_android_attribute(
                component,
                "readPermission"
            )
        )

        component_data[
            "write_permission"
        ] = (
            _get_android_attribute(
                component,
                "writePermission"
            )
        )

    return component_data


def _extract_components(
    application,
    tag_name,
    component_type,
    package_name
) -> list:
    """Extract a specific type of component."""

    components = []

    for component in application.findall(
        tag_name
    ):

        component_data = (
            _extract_component(
                component,
                component_type,
                package_name
            )
        )

        components.append(
            component_data
        )

    components.sort(
        key=lambda item: (
            item["name"] or ""
        )
    )

    return components


def _extract_application(
    application,
    package_name
) -> dict:
    """Extract application-level information."""

    if application is None:

        return {
            "name": None,
            "label": None,
            "enabled": None,
            "debuggable": None,
            "allow_backup": None,
            "uses_cleartext_traffic": None,
            "permission": None,
            "process": None
        }

    application_name = (
        _normalize_component_name(
            _get_android_attribute(
                application,
                "name"
            ),
            package_name
        )
    )

    return {
        "name": application_name,

        "label": (
            _get_android_attribute(
                application,
                "label"
            )
        ),

        "enabled": (
            _convert_boolean(
                _get_android_attribute(
                    application,
                    "enabled"
                )
            )
        ),

        "debuggable": (
            _convert_boolean(
                _get_android_attribute(
                    application,
                    "debuggable"
                )
            )
        ),

        "allow_backup": (
            _convert_boolean(
                _get_android_attribute(
                    application,
                    "allowBackup"
                )
            )
        ),

        "uses_cleartext_traffic": (
            _convert_boolean(
                _get_android_attribute(
                    application,
                    "usesCleartextTraffic"
                )
            )
        ),

        "permission": (
            _get_android_attribute(
                application,
                "permission"
            )
        ),

        "process": (
            _get_android_attribute(
                application,
                "process"
            )
        )
    }


def get_components(
    config: dict
) -> dict:
    """Extract Android application components."""

    output_dir = Path(
        config["output_dir"]
    )

    manifest_path = (
        _find_manifest(
            output_dir
        )
    )

    try:

        tree = ET.parse(
            manifest_path
        )

    except ET.ParseError as error:

        raise ValueError(
            "The decoded manifest "
            "could not be parsed."
        ) from error

    root = tree.getroot()

    package_name = (
        root.get(
            "package"
        )
    )

    application = root.find(
        "application"
    )

    if application is None:

        return {
            "application": (
                _extract_application(
                    None,
                    package_name
                )
            ),

            "activity_count": 0,

            "activities": [],

            "service_count": 0,

            "services": [],

            "receiver_count": 0,

            "receivers": [],

            "provider_count": 0,

            "providers": [],

            "exported_component_count": 0,

            "exported_components": []
        }

    activities = (
        _extract_components(
            application,
            "activity",
            "activity",
            package_name
        )
    )

    activity_aliases = (
        _extract_components(
            application,
            "activity-alias",
            "activity-alias",
            package_name
        )
    )

    activities.extend(
        activity_aliases
    )

    activities.sort(
        key=lambda item: (
            item["name"] or ""
        )
    )

    services = (
        _extract_components(
            application,
            "service",
            "service",
            package_name
        )
    )

    receivers = (
        _extract_components(
            application,
            "receiver",
            "receiver",
            package_name
        )
    )

    providers = (
        _extract_components(
            application,
            "provider",
            "provider",
            package_name
        )
    )

    all_components = (
        activities
        + services
        + receivers
        + providers
    )

    exported_components = [
        component
        for component in all_components
        if component["exported"] is True
    ]

    return {
        "application": (
            _extract_application(
                application,
                package_name
            )
        ),

        "activity_count": (
            len(activities)
        ),

        "activities": activities,

        "service_count": (
            len(services)
        ),

        "services": services,

        "receiver_count": (
            len(receivers)
        ),

        "receivers": receivers,

        "provider_count": (
            len(providers)
        ),

        "providers": providers,

        "exported_component_count": (
            len(exported_components)
        ),

        "exported_components": (
            exported_components
        )
    }