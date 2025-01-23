{
    This file is part of the Free Pascal run time library.
    Copyright (c) 2000 by Peter Vreman

    Stabs Line Info Retriever

    See the file COPYING.FPC, included in this distribution,
    for details about the copyright.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

 **********************************************************************}
{
  This unit should not be compiled in objfpc mode, since this would make it
  dependent on objpas unit.
}
unit CustomLineInfo;
interface

{$S-}
{$Q-}

function StabBackTraceStr(addr:Pointer):shortstring;

implementation

uses
  exeinfo,strings,lnfodwrf;

const
  N_Function    = $24;
  N_TextLine    = $44;
  N_DataLine    = $46;
  N_BssLine     = $48;
  N_SourceFile  = $64;
  N_IncludeFile = $84;

  maxstabs = 40; { size of the stabs buffer }

var
  { GDB after 4.18 uses offset to function begin
    in text section but OS/2 version still uses 4.16 PM }
  StabsFunctionRelative: boolean;

type
  pstab=^tstab;
  tstab=packed record
    strpos  : longint;
    ntype   : byte;
    nother  : byte;
    ndesc   : word;
    nvalue  : dword;
  end;

{ We use static variable so almost no stack is required, and is thus
  more safe when an error has occured in the program }
var
  e          : TExeFile;
  stabcnt,              { amount of stabs }
  stablen,
  stabofs,              { absolute stab section offset in executable }
  stabstrlen,
  stabstrofs : longint; { absolute stabstr section offset in executable }
  dirlength  : longint; { length of the dirctory part of the source file }
  stabs      : array[0..maxstabs-1] of tstab;  { buffer }
  funcstab,             { stab with current function info }
  linestab,             { stab with current line info }
  dirstab,              { stab with current directory info }
  filestab   : tstab;   { stab with current file info }
  filename: ansistring;
  dbgfn : string;


var
  Crc32Tbl : array[0..255] of cardinal;

procedure MakeCRC32Tbl;
var
  crc : cardinal;
  i,n : integer;
begin
  for i:=0 to 255 do
   begin
     crc:=i;
     for n:=1 to 8 do
      if (crc and 1)<>0 then
       crc:=(crc shr 1) xor cardinal($edb88320)
      else
       crc:=crc shr 1;
     Crc32Tbl[i]:=crc;
   end;
end;

Function UpdateCrc32(InitCrc:cardinal;const InBuf;InLen:LongInt):cardinal;
var
  i : LongInt;
  p : pchar;
begin

  if Crc32Tbl[1]=0 then
   MakeCrc32Tbl;
  p:=@InBuf;
  Result:=not InitCrc;
  for i:=1 to InLen do
   begin
     UpdateCrc32:=Crc32Tbl[byte(Result) xor byte(p^)] xor (Result shr 8);
     inc(p);
   end;
  Result:=not Result;
end;

function CheckDbgFile(var e:TExeFile;const fn:string;dbgcrc:cardinal):boolean;
var
  c      : cardinal;
  ofm    : word;
  g      : file;
begin
  CheckDbgFile:=false;
  assign(g,fn);
  {$I-}
   ofm:=filemode;
   filemode:=$40;
   reset(g,1);
   filemode:=ofm;
  {$I+}
  if ioresult<>0 then
   exit;
  { We reuse the buffer from e here to prevent too much stack allocation }
  c:=0;
  repeat
    blockread(g,e.buf,e.bufsize,e.bufcnt);
    c:=UpdateCrc32(c,e.buf,e.bufcnt);
  until e.bufcnt<e.bufsize;
  close(g);
  CheckDbgFile:=(dbgcrc=c);
end;

function ReadDebugLink(var e:TExeFile;var dbgfn:string):boolean;
var
  dbglink : array[0..512] of char;
  i,
  dbglinklen,
  dbglinkofs : longint;
  dbgcrc     : cardinal;
begin
  ReadDebugLink:=false;
  dbglinkofs := 0;
  dbglinklen := 0;
  dbgcrc := 0;
  if not FindExeSection(e,'.gnu_debuglink',dbglinkofs,dbglinklen) then
    exit;
  if dbglinklen>sizeof(dbglink)-1 then
    exit;
  fillchar(dbglink,sizeof(dbglink),0);
  seek(e.f,dbglinkofs);
  blockread(e.f,dbglink,dbglinklen);
  dbgfn:=strpas(dbglink);
  if length(dbgfn)=0 then
    exit;
  i:=align(length(dbgfn)+1,4);
  if (i+4)>dbglinklen then
    exit;
  move(dbglink[i],dbgcrc,4);
  { current dir }
  if CheckDbgFile(e,dbgfn,dbgcrc) then
    begin
      ReadDebugLink:=true;
      exit;
    end;
  { executable dir }
  i:=length(e.filename);
  while (i>0) and not(e.filename[i] in AllowDirectorySeparators) do
    dec(i);
  if i>0 then
    begin
      dbgfn:=copy(e.filename,1,i)+dbgfn;
      if CheckDbgFile(e,dbgfn,dbgcrc) then
        begin
          ReadDebugLink:=true;
          exit;
        end;
    end;
end;

function OpenStabs(addr : pointer) : boolean;
var
  baseaddr : pointer;
begin
  OpenStabs:=false;
  baseaddr := nil;
  GetModuleByAddr(addr,baseaddr,filename);
{$ifdef DEBUG_LINEINFO}
  writeln(stderr,filename,' Baseaddr: ',hexstr(ptruint(baseaddr),sizeof(baseaddr)*2));
{$endif DEBUG_LINEINFO}

  if not OpenExeFile(e,filename) then
    exit;
  if ReadDebugLink(e,dbgfn) then
    begin
      CloseExeFile(e);
      if not OpenExeFile(e,dbgfn) then
        exit;
    end;
  if ptruint(BaseAddr) < e.processaddress then Exit;

  e.processaddress := ptruint(baseaddr) - e.processaddress;
  StabsFunctionRelative := E.FunctionRelative;
  if FindExeSection(e,'.stab',stabofs,stablen) and
     FindExeSection(e,'.stabstr',stabstrofs,stabstrlen) then
    begin
      stabcnt:=stablen div sizeof(tstab);
      OpenStabs:=true;
    end
  else
    begin
      CloseExeFile(e);
      exit;
    end;
end;

procedure CloseStabs;
begin
  CloseExeFile(e);
end;

function StabBackTraceStr(addr:Pointer):shortstring;
var
  func,
  source : shortstring;
  hs     : string[32];
  line   : longint;
  Store  : TBackTraceStrFunc;
  Success : boolean;
begin
{$ifdef DEBUG_LINEINFO}
  writeln(stderr,'StabBackTraceStr called');
{$endif DEBUG_LINEINFO}
  { reset to prevent infinite recursion if problems inside the code PM }
  Success:=false;
  Store:=BackTraceStrFunc;
  BackTraceStrFunc:=@SysBackTraceStr;
  Success:=GetLineInfo(ptruint(addr),func,source,line);
{ create string }
{$ifdef netware}
  { we need addr relative to code start on netware }
  dec(addr,ptruint(system.NWGetCodeStart));
  StabBackTraceStr:='  CodeStart + $'+HexStr(ptruint(addr),sizeof(ptruint)*2);
{$else}
  StabBackTraceStr:='  $'+HexStr(ptruint(addr),sizeof(ptruint)*2);
{$endif}
  if func<>'' then
    Result := Result +'  '+func;
  if source<>'' then
   begin
     if func<>'' then
      Result := Result + ', ';
     if line<>0 then
      begin
        str(line,hs);
        Result := Result + ' line ' + hs;
      end;
     Result := Result + ' of ' + source;
   end;
  if Success then
    BackTraceStrFunc:=Store;
end;

initialization
  BackTraceStrFunc := @StabBackTraceStr;

finalization
  if e.isopen then
   CloseStabs;
end.
