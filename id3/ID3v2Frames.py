# @(#) $Id: ID3v2Frames.py,v 1.1 2001/08/11 07:20:54 ryanf Exp $
__version__ = "$Revision: 1.1 $"

import re, zlib
from binfuncs import *

class ID3v2Frames:
  id = ''
  compressed = 0
  dlied = 0
  encrypted = 0
  unsynched = 0
  grouped = 0
  readonly = 0
  tagalter = 0
  filealter = 0

  def __setattr__(self, name, value):
    if self.readonly == 1:
      if name != 'readonly':
        raise NameError, 'ReadOnlyFrame'
    self.__dict__[name] = value

  def setattr_safe(self, name, value):
    self.__dict__[name] = value

  def __repr__(self):
    return '<ID3v2Frames.%s (%s)>' % (self.__class__.__name__, self.id)

  def unsynch(self, flags, data):
    (data, subsmade) = re.subn('\xff', '\xff\x00', data)
    if subsmade > 0:
      flags[14] = 1
    else:
      if self.unsynched == 1:
        flags[14] = 1
      else:
        flags[14] = 0
    return (flags, data)

  def deunsynch(self, flags, data):
    if flags[14] == 1:
      data = re.sub('\xff\x00', '\xff', data)
      self.unsynched = 1
    else:
      self.unsynched = 0
    return (flags, data)

  def read_group(self, flags, data):
    if flags[9] == 1:
      grouppos = len(data) - 1
      self.groupid = data[grouppos]
      data = data[0:grouppos]
      self.grouped = 1
    return (flags, data)

  def write_group(self, flags, data):
    if self.grouped == 1:
      data += self.groupid
      flags[9] = 1
      self.dlied = 1
    return (flags, data)

  def decompress(self, flags, data):
    if flags[15] == 1:
      realdata = len(data) - 4
      data = data[0:realdata]
      self.dlied = 1
    if flags[12] == 1:
      data = zlib.decompress(data)
      self.compressed = 1
    return (flags, data)

  def compress(self, flags, data):
    oldframesize = bin2byte(bin2synchsafe(dec2bin(len(data), 28)))
    if self.compressed == 1:
      self.dlied = 1
      flags[12] = 1
      data = zlib.compress(data)
    if self.dlied == 1:
      flags[15] = 1
      data += oldframesize
    return (flags, data)

  def assemble_frame(self, data):
    flags = [0] * 16
    flags[1] = self.tagalter
    flags[2] = self.filealter
    flags[3] = self.readonly
    flags[13] = self.encrypted

    (flags, data) = self.write_group(flags, data)
    (flags, data) = self.compress(flags, data)
    (flags, data) = self.unsynch(flags, data)
    flags = bin2byte(flags)
    framesize = bin2byte(bin2synchsafe(dec2bin(len(data), 28)))
    return self.id + framesize + flags + data

  def disassemble_frame(self, frameid, flags, data):
    self.id = frameid
    (flags, data) = self.deunsynch(flags, data)
    (flags, data) = self.decompress(flags, data)
    (flags, data) = self.read_group(flags, data)
    self.encrypted = flags[13]
    self.tagalter = flags[1]
    self.filealter = flags[2]
    self.readonly = flags[3]
    return (frameid, flags, data)

class TextInfo(ID3v2Frames):
  encoding = '\x00'
  value = ''

  def import_data(self, frameid, flags, data):
    (frameid, flags, data) = self.disassemble_frame(frameid, flags, data)
    self.setattr_safe('encoding', data[0])
    self.setattr_safe('value', data[1:])
  def dump(self):
    data = self.encoding + self.value
    return self.assemble_frame(data)

class URL(ID3v2Frames):
  url = ''

  def import_data(self, frameid, flags, data):
    (frameid, flags, data) = self.disassemble_frame(frameid, flags, data)
    self.setattr_safe('url', data)
  def dump(self):
    data = self.url
    return self.assemble_frame(data)

class UserURL(ID3v2Frames):
  description = ''
  url = ''

  def import_data(self, frameid, flags, data):
    (frameid, flags, data) = self.disassemble_frame(frameid, flags, data)
    self.setattr_safe('encoding', data[0])
    (description, url) = data[1:].split('\x00', 1)
    self.setattr_safe('description', description)
    self.setattr_safe('url', url)
  def dump(self):
    data = self.encoding + self.description + '\x00' + self.url
    return self.assemble_frame(data)

class UserTextInfo(ID3v2Frames):
  encoding = ''
  description = ''
  value = ''

  def import_data(self, frameid, flags, data):
    (frameid, flags, data) = self.disassemble_frame(frameid, flags, data)
    self.setattr_safe('encoding', data[0])
    (description, value) = data[1:].split('\x00', 1)
    self.setattr_safe('description', description)
    self.setattr_safe('value', value)
  def dump(self):
    data = self.encoding + self.description + '\x00' + self.value
    return self.assemble_frame(data)

class Comment(ID3v2Frames):
  encoding = ''
  language = ''
  description = ''
  comment = ''

  def import_data(self, frameid, flags, data):
    (frameid, flags, data) = self.disassemble_frame(frameid, flags, data)
    self.setattr_safe('encoding', data[0])
    self.setattr_safe('language', data[1:4])
    (description, comment) = data[4:].split('\x00', 1)
    self.setattr_safe('description', description)
    self.setattr_safe('comment', comment)
  def dump(self):
    data = self.encoding + self.language + self.description + '\x00' + self.comment
    return self.assemble_frame(data)

class Unknown(ID3v2Frames):
  data = ''

  def import_data(self, frameid, flags, data):
    (frameid, flags, data) = self.disassemble_frame(frameid, flags, data)
    self.setattr_safe('data', data)
  def dump(self):
    return self.assemble_frame(self.data)

class MusicCDIdentifier(ID3v2Frames):
  data = ''

  def import_data(self, frameid, flags, data):
    (frameid, flags, data) = self.disassemble_frame(frameid, flags, data)
    self.setattr_safe('toc', data)
  def dump(self):
    data = self.data
    return self.assemble_frame(data)

