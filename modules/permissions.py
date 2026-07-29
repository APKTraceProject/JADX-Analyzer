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


def _get_requested_permissions(
    root
) -> list:
    """Extract requested permissions."""

    permission_tags = [
        "uses-permission",
        "uses-permission-sdk-23",
        "uses-permission-sdk-m"
    ]

    permissions = []

    for tag_name in permission_tags:

        for element in root.findall(
            tag_name
        ):

            permission_name = (
                _get_android_attribute(
                    element,
                    "name"
                )
            )

            if permission_name is None:
                continue

            permission_data = {
                "name": permission_name,
                "source": tag_name
            }

            max_sdk_version = (
                _get_android_attribute(
                    element,
                    "maxSdkVersion"
                )
            )

            if max_sdk_version is not None:

                try:

                    max_sdk_version = int(
                        max_sdk_version
                    )

                except ValueError:

                    pass

                permission_data[
                    "max_sdk_version"
                ] = max_sdk_version

            permissions.append(
                permission_data
            )

    permissions.sort(
        key=lambda item: item["name"]
    )

    return permissions


def _get_defined_permissions(
    root
) -> list:
    """Extract app-defined permissions."""

    permissions = []

    for element in root.findall(
        "permission"
    ):

        permission_name = (
            _get_android_attribute(
                element,
                "name"
            )
        )

        if permission_name is None:
            continue

        permissions.append(
            {
                "name": permission_name,

                "protection_level": (
                    _get_android_attribute(
                        element,
                        "protectionLevel"
                    )
                ),

                "label": (
                    _get_android_attribute(
                        element,
                        "label"
                    )
                ),

                "description": (
                    _get_android_attribute(
                        element,
                        "description"
                    )
                )
            }
        )

    permissions.sort(
        key=lambda item: item["name"]
    )

    return permissions


def _get_unique_permission_names(
    permissions: list
) -> list:
    """Return unique permission names."""

    permission_names = {
        permission["name"]
        for permission in permissions
    }

    return sorted(
        permission_names
    )


def get_permissions(
    config: dict
) -> dict:
    """Extract APK permission information."""

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

    requested_permissions = (
        _get_requested_permissions(
            root
        )
    )

    defined_permissions = (
        _get_defined_permissions(
            root
        )
    )

    unique_permissions = (
        _get_unique_permission_names(
            requested_permissions
        )
    )

    return {
        "requested_count": len(
            requested_permissions
        ),

        "unique_requested_count": len(
            unique_permissions
        ),

        "requested_permissions": (
            requested_permissions
        ),

        "defined_count": len(
            defined_permissions
        ),

        "defined_permissions": (
            defined_permissions
        )
    }