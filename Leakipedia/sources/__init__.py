"""Import all source modules to trigger registration via @register_source."""

from Leakipedia.sources.base import SOURCE_REGISTRY  # noqa: F401
from Leakipedia.sources.crtsh import CrtshSource  # noqa: F401
from Leakipedia.sources.data_brokers import DataBrokersSource  # noqa: F401
from Leakipedia.sources.dehashed_free import LeakCheckSource  # noqa: F401
from Leakipedia.sources.duckduckgo_search import DuckDuckGoSearchSource  # noqa: F401
from Leakipedia.sources.exiftool_scan import ExifToolScanSource  # noqa: F401
from Leakipedia.sources.github_search import GitHubSearchSource  # noqa: F401
from Leakipedia.sources.google_search import GoogleSearchSource  # noqa: F401
from Leakipedia.sources.gravatar import GravatarSource  # noqa: F401
from Leakipedia.sources.haveibeensold import HaveIBeenSoldSource  # noqa: F401
from Leakipedia.sources.hibp import HIBPSource  # noqa: F401
from Leakipedia.sources.holehe_scan import HoleheScanSource  # noqa: F401
from Leakipedia.sources.hunter import HunterSource  # noqa: F401
from Leakipedia.sources.maigret_scan import MaigretScanSource  # noqa: F401
from Leakipedia.sources.numverify import NumVerifySource  # noqa: F401
from Leakipedia.sources.paste_search import PasteSearchSource  # noqa: F401
from Leakipedia.sources.phoneinfoga_scan import PhoneInfogaScanSource  # noqa: F401
from Leakipedia.sources.pwnedpasswords import PwnedPasswordsSource  # noqa: F401
from Leakipedia.sources.sherlock_scan import SherlockScanSource  # noqa: F401
from Leakipedia.sources.wayback import WaybackSource  # noqa: F401
from Leakipedia.sources.whois_lookup import WhoisSource  # noqa: F401
