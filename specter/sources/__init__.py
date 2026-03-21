"""Import all source modules to trigger registration via @register_source."""

from specter.sources.base import SOURCE_REGISTRY  # noqa: F401
from specter.sources.crtsh import CrtshSource  # noqa: F401
from specter.sources.data_brokers import DataBrokersSource  # noqa: F401
from specter.sources.dehashed_free import LeakCheckSource  # noqa: F401
from specter.sources.duckduckgo_search import DuckDuckGoSearchSource  # noqa: F401
from specter.sources.exiftool_scan import ExifToolScanSource  # noqa: F401
from specter.sources.github_search import GitHubSearchSource  # noqa: F401
from specter.sources.google_search import GoogleSearchSource  # noqa: F401
from specter.sources.gravatar import GravatarSource  # noqa: F401
from specter.sources.haveibeensold import HaveIBeenSoldSource  # noqa: F401
from specter.sources.hibp import HIBPSource  # noqa: F401
from specter.sources.holehe_scan import HoleheScanSource  # noqa: F401
from specter.sources.hunter import HunterSource  # noqa: F401
from specter.sources.maigret_scan import MaigretScanSource  # noqa: F401
from specter.sources.numverify import NumVerifySource  # noqa: F401
from specter.sources.paste_search import PasteSearchSource  # noqa: F401
from specter.sources.phoneinfoga_scan import PhoneInfogaScanSource  # noqa: F401
from specter.sources.pwnedpasswords import PwnedPasswordsSource  # noqa: F401
from specter.sources.sherlock_scan import SherlockScanSource  # noqa: F401
from specter.sources.wayback import WaybackSource  # noqa: F401
from specter.sources.whois_lookup import WhoisSource  # noqa: F401
