from metadata_parser import MetadataParser

if 1:
	a= MetadataParser(url='http://cnn.com')
	print a.get_metadata('title')
	
	b= MetadataParser(url='http://nyt.com')
	print b.get_metadata('title')
	
	c= MetadataParser(url='http://thedailybeast.com')
	print c.get_metadata('title')

	print "\n-------------------------------------------------------\n"
	print a.metadata
	print "\n-------------------------------------------------------\n"
	print b.metadata
	print "\n-------------------------------------------------------\n"
	print c.metadata
	print "\n-------------------------------------------------------\n"

	print c.get_metadata('title')
	print c.get_metadata('canonical')
	print c.get_metadata('url')
	print c.absolute_url(c.get_metadata('canonical'))
	print c.absolute_url(c.get_metadata('url'))
	print c.get_discrete_url()