import re
from binfuncs import *

class ID3v1:
  fh = None

  title = ''
  artist = ''
  album = ''
  year = ''
  comment = ''
  genre = 0
  track = None

  genres = [
    'Blues', 'Classic Rock', 'Country',
    'Dance', 'Disco', 'Funk',
    'Grunge', 'Hip - Hop', 'Jazz',
    'Metal', 'New Age', 'Oldies',
    'Other', 'Pop', 'R&B',
    'Rap', 'Reggae', 'Rock',
    'Techno', 'Industrial', 'Alternative',
    'Ska', 'Death Metal', 'Pranks',
    'Soundtrack', 'Euro - Techno', 'Ambient',
    'Trip - Hop', 'Vocal', 'Jazz + Funk',
    'Fusion', 'Trance', 'Classical',
    'Instrumental', 'Acid', 'House',
    'Game', 'Sound Clip', 'Gospel',
    'Noise', 'Alt Rock', 'Bass',
    'Soul', 'Punk', 'Space',
    'Meditative', 'Instrumental Pop', 'Instrumental Rock',
    'Ethnic', 'Gothic', 'Darkwave',
    'Techno - Industrial', 'Electronic', 'Pop - Folk',
    'Eurodance', 'Dream', 'Southern Rock',
    'Comedy', 'Cult', 'Gangsta Rap',
    'Top 40', 'Christian Rap', 'Pop / Funk',
    'Jungle', 'Native American', 'Cabaret',
    'New Wave', 'Psychedelic', 'Rave',
    'Showtunes', 'Trailer', 'Lo - Fi',
    'Tribal', 'Acid Punk', 'Acid Jazz',
    'Polka', 'Retro', 'Musical',
    'Rock & Roll', 'Hard Rock', 'Folk',
    'Folk / Rock', 'National Folk', 'Swing',
    'Fast - Fusion', 'Bebob', 'Latin',
    'Revival', 'Celtic', 'Bluegrass',
    'Avantgarde', 'Gothic Rock', 'Progressive Rock',
    'Psychedelic Rock', 'Symphonic Rock', 'Slow Rock',
    'Big Band', 'Chorus', 'Easy Listening',
    'Acoustic', 'Humour', 'Speech',
    'Chanson', 'Opera', 'Chamber Music',
    'Sonata', 'Symphony', 'Booty Bass',
    'Primus', 'Porn Groove', 'Satire',
    'Slow Jam', 'Club', 'Tango',
    'Samba', 'Folklore', 'Ballad',
    'Power Ballad', 'Rhythmic Soul', 'Freestyle',
    'Duet', 'Punk Rock', 'Drum Solo',
    'A Cappella', 'Euro - House', 'Dance Hall',
    'Goa', 'Drum & Bass', 'Club - House',
    'Hardcore', 'Terror', 'Indie',
    'BritPop', 'Negerpunk', 'Polsk Punk',
    'Beat', 'Christian Gangsta Rap', 'Heavy Metal',
    'Black Metal', 'Crossover', 'Contemporary Christian',
    'Christian Rock', 'Merengue', 'Salsa',
    'Thrash Metal', 'Anime', 'JPop',
    'Synthpop'
  ]

  def __init__(self, fh):
    self.fh = fh
    self.load()

  def load(self):
    currentpos = self.fh.tell()
    self.fh.seek(0, 2)
    if self.fh.tell() > 127:
      self.fh.seek(-128, 2)
      id3tag = self.fh.read(128)
      if id3tag[0:3] == 'TAG':
        self.title = re.sub('\x00+$', '', id3tag[3:33].rstrip())
        self.artist = re.sub('\x00+$', '', id3tag[33:63].rstrip())
        self.album = re.sub('\x00+$', '', id3tag[63:93].rstrip())
        self.year = re.sub('\x00+$', '', id3tag[93:97].rstrip())
        self.comment = re.sub('\x00+$', '', id3tag[97:127].rstrip())
        self.genre = ord(id3tag[127:128])
        if self.comment[28:29] == '\x00':
          self.track = ord(self.comment[29:30])
          self.comment = re.sub('\x00+$', '', self.comment[0:28].rstrip())
        else:
          self.track = None
    self.fh.seek(currentpos)

  def save(self):
    self.title = self.title[0:30]
    self.artist = self.artist[0:30]
    self.album = self.album[0:30]
    self.year = self.year[0:4]
    if self.track != None:
      self.comment = self.comment[0:28]
    else:
      self.comment = self.comment[0:30]
    id3tag = 'TAG'
    id3tag += self.title + ('\x00' * (30 - len(self.title)))
    id3tag += self.artist + ('\x00' * (30 - len(self.artist)))
    id3tag += self.album + ('\x00' * (30 - len(self.album)))
    id3tag += self.year + ('\x00' * (4 - len(self.year)))
    if self.track != None:
      id3tag += self.comment + ('\x00' * (29 - len(self.comment)))
      id3tag += chr(self.track)
    else:
      id3tag += self.comment + ('\x00' * (30 - len(self.comment)))
    id3tag += chr(self.genre)
    currentpos = self.fh.tell()
    self.fh.seek(0, 2)
    if self.fh.tell() > 127:
      self.fh.seek(-128, 2)
      oldid3tag = self.fh.read(3)
      if oldid3tag == 'TAG':
        currentpos = self.fh.tell()
        self.fh.seek(-128, 2)
        self.fh.write(id3tag)
      else:
        self.fh.seek(0, 2)
        self.fh.write(id3tag)
    else:
      self.fh.write(id3tag)
    self.fh.seek(currentpos)
    

class ID3v2:
  version_minor = 0
  version_rev = 0
  tag_size = 0
  padding_size = 0
  unsync = 0
  extended = 0
  experimental = 0
  footer = 0
  frames = []

  fh = None

  def __init__(self, fh):
    self.fh = fh
    self.load()

  def load(self):
    self.fh.seek(3)
    verinfo = self.fh.read(2)
    self.version_minor = ord(verinfo[0])
    self.version_rev = ord(verinfo[1])
    (
      self.unsync,
      self.extended,
      self.experimental,
      self.footer,
      None,
      None,
      None,
      None
    ) = byte2bin(self.fh.read(1), 8)
    self.tag_size = bin2dec(byte2bin(self.fh.read(4), 7))
    sizeleft = self.tag_size
    while sizeleft > 0:
      frameid = self.fh.read(4)
      if frameid != '\x00\x00\x00\x00':
        framesize = bin2dec(byte2bin(self.fh.read(4), 7))
        foo = self.fh.read(2)
        flags = byte2bin(foo, 8)
        data = self.fh.read(framesize)
        sizeleft -= (framesize + 10)
        print "ID %s\nsize %s\nflags %s\n" % (frameid, framesize, flags)
        self.frames.append(self.makeframedisplay(frameid, flags, data))
      else:
        self.padding_size = sizeleft
        return

  def dump(self):
    out2 = 'ID3'
    out2 += chr(self.version_minor)
    out2 += chr(self.version_rev)
    out2 += bin2byte([
      self.unsync,
      self.extended,
      self.experimental,
      self.footer,
      0,
      0,
      0,
      0
    ])
    out = ''
    for i in self.frames:
      out += i.dump()
    out += '\x00' * self.padding_size
    tagsize = bin2byte(bin2synchsafe(dec2bin(len(out), 28)))
    out2 += tagsize
    return out2 + out

  def makeframedisplay(self, frameid, flags, data):
    print flags
    if frameid[0] == 'T':
      if frameid == 'TXXX':
        pass
      else:
        return ID3v2TextInfoFrame(frameid, flags, data)
    return ID3v2UnknownFrame(frameid, flags, data)


class ID3v2Frame:
  def unsynch(flags, data):
    pass

class ID3v2TextInfoFrame:
  def __init__(self, frameid, flags, data):
    self.id = frameid
    self.flags = flags
    print flags
    print repr(bin2byte(flags))
    self.encoding = data[0]
    self.value = data[1:]
  def dump(self):
    data = self.encoding + self.value
    framesize = bin2byte(bin2synchsafe(dec2bin(len(data), 28)))
    flags = bin2byte(self.flags)
    return self.id + framesize + flags + data

class ID3v2UnknownFrame:
  def __init__(self, frameid, flags, data):
    self.id = frameid
    self.flags = flags
    self.data = data
  def dump(self):
    framesize = bin2byte(bin2synchsafe(dec2bin(len(self.data), 28)))
    flags = bin2byte(self.flags)
    return self.id + framesize + flags + self.data

