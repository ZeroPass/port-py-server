from pymrtd import ef
from typing import Final, List, NamedTuple
from .types import CountryCode

class FilterListHash(NamedTuple):
    algo: str
    hash: bytes

    def __eq__(self, other: 'FilterListHash') -> bool:
        return self.algo == other.algo and self.hash == other.hash

    def __ne__(self, other: 'FilterListHash') -> bool:
        return not (self == other)

class LdsHashFilterList(dict[ef.DataGroupNumber, List[FilterListHash]]):
    """
    Dictionary contains whitlisted hash values mapped to data group numbers
    """
    def contains(self, dgNumber: ef.DataGroupNumber, hash: FilterListHash): #pylint: disable=redefined-builtin
        """
        Returns True if list contains `hash` under `dgNumber`.
        """
        for h in self[dgNumber]:
            if h == hash:
                return True
        return False

    def __setitem__(self, dgNumber: ef.DataGroupNumber, list: List[FilterListHash]) -> None: #pylint: disable=redefined-builtin
        if not isinstance(dgNumber, ef.DataGroupNumber):
            raise KeyError('Argument dgNumber is not of type ef.DataGroupNumber')
        if not isinstance(list, List):
            raise KeyError('Argument list is not of type List[FilterListHash]')
        return super().__setitem__(dgNumber, list)

    def __getitem__(self, dgNumber: ef.DataGroupNumber) -> List[FilterListHash]:
        """
        Returns list of `FilterlistHash` or empty list if list doesn't contain `dgNumber`.
        """
        assert isinstance(dgNumber, ef.DataGroupNumber)
        return super().__getitem__(dgNumber) if dgNumber in self else []

    def getList(self, dgNumber: ef.DataGroupNumber) -> List[FilterListHash]:
        return self[dgNumber]

class CountryLdsFilterList(dict[CountryCode, LdsHashFilterList]):
    """ Dictionary contains list of filtered LDS DataGroup hashes for country. """

    def __setitem__(self, country: CountryCode, filterlist: LdsHashFilterList) -> None:
        if not isinstance(country, CountryCode):
            raise KeyError('Argument country is not of type CountryCode')
        if not isinstance(filterlist, List):
            raise KeyError('Argument list is not of type FilterListHash')
        return super().__setitem__(country, filterlist)

    def __getitem__(self, country: CountryCode) -> LdsHashFilterList:
        """
        Returns list of `FilterListHash`for `country`.
        """
        return super().__getitem__(country) if country in self else LdsHashFilterList()

    def getList(self, country: CountryCode) -> LdsHashFilterList:
        return self[country]


# Preset fixed LDS hash whitelist
ldsMatchWhitelist: Final[CountryLdsFilterList] = CountryLdsFilterList({
    CountryCode('CN') : LdsHashFilterList({
        ef.DataGroupNumber(12) : [
            # Empty DG12 file with 2 0x5F1B tags for Endorsement/Observation
            # Raw file: 6C075C025F1B5F1B00
            FilterListHash( 'sha256', bytes.fromhex('AE4BBA015B391DF89EE3365C8C184FFCF9BB7E825A30077B73877278974E7A28') )
        ]
    })
})
