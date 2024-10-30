from microschc.parser import PdmlParser,PyPdmlParserError

def test_pdmlParser_file_open():
    pdmlFileName:str = 'FakeFile.pdml'
    # test false file name
    pdmlParser:PdmlParser = PdmlParser()
    try:
        pdmlParser.parseFromFile(pdmlFileName=pdmlFileName)
        assert False
    except PyPdmlParserError:
        assert True
    # test directory
    pdmlFileName:str = '/home/'
    try:
        pdmlParser.parseFromFile(pdmlFileName=pdmlFileName)
        assert False
    except PyPdmlParserError:
        assert True
    