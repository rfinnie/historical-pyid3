import re, os
import ID3v2Frames
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


  def load(self, fn):
    fh = open(fn, 'rb')
    fh.seek(3)
    verinfo = fh.read(2)
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
    ) = byte2bin(fh.read(1), 8)
    self.tag_size = bin2dec(byte2bin(fh.read(4), 7))
    sizeleft = self.tag_size
    while sizeleft > 0:
      frameid = fh.read(4)
      if frameid != '\x00\x00\x00\x00':
        framesize = bin2dec(byte2bin(fh.read(4), 7))
        foo = fh.read(2)
        flags = byte2bin(foo, 8)
        data = fh.read(framesize)
        sizeleft -= (framesize + 10)
        print "ID %s\nsize %s\nflags %s\n" % (frameid, framesize, flags)
        self.frames.append(self.makeframedisplay(frameid, flags, data))
      else:
        self.padding_size = sizeleft
        break
    fh.close()

  def dump(self, fn):
    fh = open(fn, 'rb+')
    fh.seek(3)
    verinfo = fh.read(2)
    version_minor = ord(verinfo[0])
    version_rev = ord(verinfo[1])
    (
      unsync,
      extended,
      experimental,
      footer,
      None,
      None,
      None,
      None
    ) = byte2bin(fh.read(1), 8)
    old_tag_size = bin2dec(byte2bin(fh.read(4), 7))
    self.unsync = 1
    out = ''
    for i in self.frames:
      out += i.dump()
    if len(out) > old_tag_size:
      expand_file = 1
      out += '\x00' * 2048
    else:
      expand_file = 0
      out += '\x00' * (old_tag_size - len(out))

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
    tagsize = bin2byte(bin2synchsafe(dec2bin(len(out), 28)))
    out2 += tagsize


    if expand_file == 1:
      fh.seek(old_tag_size + 10)
      fh2 = open(fn + '.temp', 'wb')
      fh2.write(out2)
      fh2.write(out)
      fh2.write(fh.read())
      fh2.close()
      fh.close()
      os.rename(fn + '.temp', fn)
    else:
      fh.seek(0)
      fh.write(out2)
      fh.write(out)
      fh.close()
    return

  def makeframedisplay(self, frameid, flags, data):
    if frameid[0] == 'T':
      if frameid == 'TXXX':
        pass
      else:
        x = ID3v2Frames.TextInfo()
        x.import_data(frameid, flags, data)
        return x
    elif frameid[0] == 'C':
      if frameid == 'COMM':
        x = ID3v2Frames.Comment()
        x.import_data(frameid, flags, data)
        return x
      else:
        pass
    elif frameid[0] == 'W':
      if frameid == 'WXXX':
        x = ID3v2Frames.UserURL()
        x.import_data(frameid, flags, data)
        return x
      else:
        pass
    x = ID3v2Frames.Unknown()
    x.import_data(frameid, flags, data)
    return x

