unit qnx6.tests;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils, fpcunit, testregistry,
  qnx6, qnx6.types, uMisc;

type
  { TTestQNX6Fs }

  TTestQNX6Fs = class(TTestCase)
  private
    FStream: TMemoryStream;
    FFs: TQNX6Fs;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestCreateImage;
    procedure TestCreateFileAndReadDir;
    procedure TestMkDir;
    procedure TestRemoveFile;
    procedure TestRename;
    procedure TestKernelLongNameChecksums;
  end;

implementation

procedure TTestQNX6Fs.TestKernelLongNameChecksums;
var
  name: UTF8String;
begin
  name := 'libAppWorldStoreFront.so.1.0.0';
  AssertEquals('App World filename lookup checksum', Int64($7fffc8d0),
    Int64(qnx6_lfile_checksum(@name[1], Length(name))));
  name := 'cert_E0AB059420725493056062023670F7CD2EFC6666.pem';
  AssertEquals('Certificate filename lookup checksum', Int64($994a99a0),
    Int64(qnx6_lfile_checksum(@name[1], Length(name))));
  AssertEquals('Empty filename checksum', Int64(0), Int64(qnx6_lfile_checksum(nil, 0)));
end;

procedure TTestQNX6Fs.SetUp;
begin
  inherited SetUp;
  FStream := TMemoryStream.Create;
  FFs := TQNX6Fs.Create(FStream);
end;

procedure TTestQNX6Fs.TearDown;
begin
  FreeAndNil(FFs);
  FreeAndNil(FStream);
  inherited TearDown;
end;

procedure TTestQNX6Fs.TestCreateImage;
begin
  // Форматуємо 1024 блоки по 512 байт, 64 іноди
  FFs.CreateImage(1024, 512, 64);

  AssertEquals('BlockSize має бути 512', 512, FFs.BlockSize);
  AssertEquals('Загальна кількість інод має бути 64', 64, FFs.GetInodeCount);
  AssertEquals('Вільних інод має бути 62 (1 і 2 зайняті під / та /boot)', 62, FFs.GetFreeInodeCount);
end;

procedure TTestQNX6Fs.TestCreateFileAndReadDir;
var
  Res: integer;
  DE: TQNX6_ARawDirEntry;
  Found: boolean;
  I: integer;
begin
  FFs.CreateImage(1024, 512, 64);
  FFs.Open(True);

  // Створюємо файл у корені
  Res := FFs.CreateFile('/test_file.txt', &644);
  AssertEquals('Створення файлу має повернути 0 (Успіх)', 0, Res);

  // Читаємо каталог
  Res := FFs.ReadDirectory('/', DE);
  AssertTrue('ReadDirectory має повернути > 0 елементів', Res > 0);

  Found := False;
  for I := 0 to High(DE) do
  begin
    if FFs.RawDirEntryGetName(DE[I]) = 'test_file.txt' then
    begin
      Found := True;
      Break;
    end;
  end;

  AssertTrue('Файл test_file.txt має бути присутній у списку директорії', Found);
end;

procedure TTestQNX6Fs.TestMkDir;
var
  Res: integer;
  InodeIdx: DWord;
begin
  FFs.CreateImage(1024, 512, 64);
  FFs.Open(True);

  Res := FFs.MkDir('/my_folder', &755);
  AssertTrue('MkDir має повернути ID створеного іноду (> 0)', Res > 0);

  InodeIdx := FFs.GetInodeByPath('/my_folder');
  AssertEquals('GetInodeByPath має знайти новий каталог', Res, InodeIdx);
end;

procedure TTestQNX6Fs.TestRemoveFile;
var
  Res: integer;
  InodeIdx: DWord;
begin
  FFs.CreateImage(1024, 512, 64);
  FFs.Open(True);

  FFs.CreateFile('/delete_me.txt', &644);
  InodeIdx := FFs.GetInodeByPath('/delete_me.txt');
  AssertTrue('Файл існує перед видаленням', InodeIdx > 0);

  Res := FFs.removeFileDir('/delete_me.txt', False);
  AssertEquals('Видалення файлу має повернути 0', 0, Res);

  InodeIdx := FFs.GetInodeByPath('/delete_me.txt');
  AssertEquals('Файл не повинен знаходитися після видалення', 0, InodeIdx);
end;

procedure TTestQNX6Fs.TestRename;
var
  Res: integer;
  OldInode, NewInode: DWord;
begin
  FFs.CreateImage(1024, 512, 64);
  FFs.Open(True);

  FFs.CreateFile('/old_name.txt', &644);
  OldInode := FFs.GetInodeByPath('/old_name.txt');

  Res := FFs.Rename('/old_name.txt', '/new_name.txt');
  AssertEquals('Перейменування має повернути 0', 0, Res);

  AssertEquals('За старим шляхом об''єкт не знайдено', 0, FFs.GetInodeByPath('/old_name.txt'));
  NewInode := FFs.GetInodeByPath('/new_name.txt');
  AssertEquals('Новий шлях має вказувати на той самий inode', OldInode, NewInode);
end;

initialization
  RegisterTest(TTestQNX6Fs);
end.
