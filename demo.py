from metadata_parser import MetadataParser

if 0:
    a= MetadataParser(url='http://cnn.com')
    print(a.get_metadata('title'))

    b= MetadataParser(url='http://nyt.com')
    print(b.get_metadata('title'))

    c= MetadataParser(url='http://thedailybeast.com')
    print(c.get_metadata('title'))

    print("\n-------------------------------------------------------\n")
    print(a.metadata)
    print("\n-------------------------------------------------------\n")
    print(b.metadata)
    print("\n-------------------------------------------------------\n")
    print(c.metadata)
    print("\n-------------------------------------------------------\n")

    print(c.get_metadata('title'))
    print(c.get_metadata('canonical'))
    print(c.get_metadata('url'))
    print(c.absolute_url(c.get_metadata('canonical')))
    print(c.absolute_url(c.get_metadata('url')))
    print(c.get_discrete_url())

if 0:
    a= MetadataParser(url='http://liqr.co/rsvpnewyork')
    print("title:")
    print(a.get_metadata('title'))
    print("canonical:")
    print(a.get_metadata('canonical'))
    print("url:")
    print(a.get_metadata('url'))
    print("absolute_url-canonical:")
    print(a.absolute_url(a.get_metadata('canonical')))
    print("absolute_url-url:")
    print(a.absolute_url(a.get_metadata('url')))
    print("get_discrete_url:")
    print(a.get_discrete_url())


if 0:
    a= MetadataParser(url='http://www.ted.com/talks/drew_curtis_how_i_beat_a_patent_troll.html')
    print(a.__dict__)

if 0:
    broken_html= open('broken.html','r').read()
    #a= MetadataParser(url="http://brewskeeball.com/rosenblog")
    a= MetadataParser(html=broken_html)
    print(a.get_metadata('title'))


if 0:
    urls = [\
        'http://www.cnn.com',
        'http://www.cnn.com/',
        'http://www.michaeleisen.org/blog/?p=358',
        'http://www.nasa.gov/externalflash/discovery/index.html',
        'http://hw.libsyn.com/p/d/d/6/dd6b0db2d4858640/ARIYNBF_107_JamesGunn.mp3?sid=78edb823ad1b62ff6f329d68bbb2cc6a&l_sid=35168&l_eid=&l_mid=2952818&expiration=1334720066&hwt=7acfe1754c8dedc4f134b473894c9208'
    ]
    for i in urls:
        a= MetadataParser(url=i)
        print(a.__dict__)

if 0:
    url = 'http://soundcloud.com/electricyouthmusic'
    a= MetadataParser(url=url)
    print(a.__dict__)
