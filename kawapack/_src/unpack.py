from UnityPy import Environment
from UnityPy.classes import Object, Sprite, Texture2D, TextAsset, AudioClip, MonoBehaviour
from UnityPy.enums import ClassIDType as Obj
from pathlib import Path
import json
import bson
from Crypto.Cipher import AES
from fsb5 import FSB5
from warnings import warn
from PIL import Image
import pydub
import io
import subprocess
from wannacri.wannacri import *
import hashlib

FBS_FILES = []
# FBS unpacking requires 2 things:
# 1. clone https://github.com/MooncellWiki/OpenArknightsFBS.git into /arkdata
# 2. build flatc and add to path (or put the executable in the /arkdata dir)
if Path(r".\OpenArknightsFBS\FBS").exists():
    FBS_FILES = [p for p in Path(r".\OpenArknightsFBS\FBS").glob('*.fbs')]

def get_target_path(obj: Object, source_dir: Path, output_dir: Path) -> Path:
    resource = obj.read()
    if obj.container:
        parts = Path(obj.container).parts
        if (len(parts)>2 and parts[-3] == 'charavatars'):
            # flatten the charavatars dir (normally has subdirs "elite" and "skins")
            source_dir = Path('torappu','dynamicassets',*parts[1:-2])
        else:
            source_dir = Path('torappu','dynamicassets',*parts[1:-1])

    # if isinstance(obj, MonoBehaviour) and (script := obj.m_Script):
        # return Path(str(output_dir / source_dir / script.read().name).lower())

    assert isinstance(resource.m_Name, str)
    return Path(str(output_dir / source_dir / resource.m_Name).lower())


# Some assets have identical file paths, so unique
# file names are generated to prevent overwriting data.
def get_available_path(path: Path) -> Path:
    if path.is_file():
        path = path.with_stem(path.stem + "_1")
        index = 1
        while path.is_file():
            index += 1
            new_name = f"_{index}".join(path.stem.rsplit(f"_{index-1}", 1))
            path = path.with_stem(new_name)
    return path


def write_bytes(data: bytes, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def write_object(data: object, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path.with_suffix(".json"), "w", encoding="utf8") as f:
        json.dump(data, f, ensure_ascii=False, indent=4)


def write_binary_object(data: bytes, path: Path) -> None:
    try:
        # BSON decoding fails if data is JSON-encoded BSON instead of plain BSON
        decoded = bson.decode(data)
        write_object(decoded, path)
    except:
        write_object(json.loads(data), path)


def decrypt_textasset(stream: bytes) -> bytes:
    def unpad(data: bytes) -> bytes:
        end_index = len(data) - data[-1]
        return data[:end_index]

    CHAT_MASK = bytes.fromhex('554954704169383270484157776e7a7148524d4377506f6e4a4c49423357436c').decode()

    aes_key = CHAT_MASK[:16].encode()
    aes_iv = bytearray(
        buffer_bit ^ mask_bit
        for (buffer_bit, mask_bit) in zip(stream[:16], CHAT_MASK[16:].encode())
    )

    decrypted = (
        AES.new(aes_key, AES.MODE_CBC, aes_iv)
        .decrypt(stream[16:])
    )

    return unpad(decrypted)


def export(env: Environment, _orig: Object, target_path: Path) -> None:
    obj = _orig.read()
    match obj:
        case Sprite() | Texture2D():
            if (img := obj.image).width > 0:
                target_path.parent.mkdir(parents=True, exist_ok=True)
                img.save(target_path.with_suffix(".png"))

        case TextAsset():
            target_path_str = target_path.as_posix()
            data = bytes(obj.script)
            if "gamedata/story" in target_path_str:
                # Story text is unencrypted, so the data can be saved without further changes
                write_bytes(data, target_path.with_suffix(".txt"))
            elif "gamedata/levels/" in target_path_str:
                try:
                    # Level data is only encrypted for US server. Attempts to decrypt CN data will fail.
                    data = decrypt_textasset(data)
                    write_binary_object(data, target_path)
                except:
                    try:
                        # Extraneous starting bytes must be removed before attempting to parse as BSON
                        write_binary_object(data[128:], target_path)
                    except:
                        warn(f"Failed to save data to {target_path}", RuntimeWarning)
                        # if "obt/memory" in target_path_str:
                        #     data = decrypt_textasset(data[(256 + len(data) % 16):])
                        #     ...
                        # write_bytes(data, target_path)
            else:
                try:
                    # Decryption will fail if the data is not actually encrypted
                    # Extraneous starting bytes must be removed before attempting decryption
                    data = decrypt_textasset(data[128:])
                    write_binary_object(data, target_path)
                except:
                    try:
                        write_object(json.loads(data), target_path)
                    except:
                        for fbs in FBS_FILES:
                            if obj.name.startswith(fbs.stem):
                                # is a flatbuffer, convert to json:
                                raw = target_path.with_name(fbs.stem)
                                write_bytes(data[128:], raw) # The first leading 128 bytes are RSA signature from Hypergryph to ensure the integrity of tables.
                                command = ["flatc",'--json','-o',str(target_path.parent),'--raw-binary',str(fbs),'--',str(raw),'--strict-json', '--natural-utf8', '--defaults-json','--no-warnings']
                                # print( ' '.join(command))
                                try:
                                    subprocess.run(command, check=True)
                                except subprocess.CalledProcessError as e:
                                    write_bytes(data, target_path)
                                finally:
                                    raw.unlink()
                                break
                        else:
                            write_bytes(data, target_path)

        case AudioClip():
            # UnityPy doesn't load m_AudioData correctly, this may have something to do with the compression/encryption change in AK v2.5
            # for now we will extract it manually instead:
            audio_bytes = obj.m_AudioData
            if not audio_bytes:
                source_file = obj.m_Resource.m_Source
                offset = obj.m_Resource.m_Offset
                size = obj.m_Resource.m_Size            
                for bundle in env.files.values():
                    for name, reader in bundle.files.items():
                        if source_file.endswith(name):
                            # found matching file, read bytes from offset
                            reader.Position = offset
                            audio_bytes = bytes(reader.read(size))
            # immediately convert to mp3 with pydub
            fsb = FSB5(audio_bytes)
            assert len(fsb.samples) == 1
            # target_path = target_path.with_suffix("." + fsb.get_sample_extension())

            try:
                # Audio clip conversion will fail if DLLs needed by fsb5
                # (libogg, libvorbis, libvorbisenc, libvorbisfile) cannot be found
                # or the CRC32 value associated with the file format is incorrect.
                target_path.parent.mkdir(parents=True, exist_ok=True)
                sample = fsb.rebuild_sample(fsb.samples[0])
                s = io.BytesIO(sample)
                s.seek(0)
                pydub.AudioSegment.from_file(s).export(target_path.with_suffix('.mp3'), format='mp3')
                # write_bytes(sample, target_path)
            except:
                warn(f"Failed to save audio clip to {target_path}", RuntimeWarning)
                raise

        case MonoBehaviour():
            if obj.m_Name:
                tree = _orig.read_typetree()
                target_path = get_available_path(
                    target_path.joinpath(obj.m_Name).with_suffix(".json")
                )
                write_object(tree, target_path)


def extract_from_env(env: Environment, source_dir: Path, output_dir: Path, raw_data, filename):
    print('extracting from', filename, flush = True)
    source_path_parts = set(source_dir.parts)
    if "chararts" in source_path_parts or "skinpack" in source_path_parts:
        for object in env.objects:
            if object.type == Obj.Texture2D:
                resource = object.read()
                if isinstance(resource, Texture2D) and resource.m_Width > 512 and resource.m_Height > 512:
                    target_path = get_target_path(object, source_dir, output_dir)
                    export(env, object, target_path)
    elif "avg" in source_path_parts and "characters" in source_path_parts:
        extract_character_with_faces(env, Path(str(source_dir).lower()), Path(str(output_dir).lower()))
    elif "video" in source_path_parts:
        # not a unity object, just a raw mp4 file.
        dest_path = (output_dir / source_dir / filename.replace('.usm','.mp4'))
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        extract_usm_video(raw_data, dest_path)
    else:
        for object in env.objects:
            if object.type in {Obj.Sprite, Obj.Texture2D, Obj.TextAsset, Obj.AudioClip, Obj.MonoBehaviour}:
                resource = object.read()
                if isinstance(resource, Object):
                    target_path = get_target_path(object, source_dir, output_dir)
                    export(env, object, target_path)

def extract_usm_video(raw_data, dest_path):
    fname = int(hashlib.md5(str(dest_path).encode('utf-8')).hexdigest(), 16)
    usm = Usm.open(None, encoding="gb18030", key=None, raw_bytes = raw_data)
    outfiles = usm.demux(
        path='./TMP_VIDEO_MUXING',
        save_video=True,
        save_audio=True,
        save_pages=False,
        folder_name=fname,
    )
    flat_files = [x for xs in outfiles for x in xs]
    command = ['ffmpeg','-y']
    command.extend(sum([['-i', x] for x in flat_files], []))
    command.extend([dest_path])
    subprocess.run(command,check=True)

    # poster image @ 1.5s
    poster_output = dest_path.with_name(dest_path.stem + "_poster.jpg")

    extract_frame_cmd = [
        'ffmpeg',
        '-y',
        '-ss', '1.5',
        '-i', str(dest_path),
        '-frames:v', '1',
        '-q:v', '2',  # high-quality JPEG
        str(poster_output)
    ]
    subprocess.run(extract_frame_cmd, check=True)
def extract_character_with_faces(env: Environment, source_dir: Path, output_dir: Path):
    path_map = {}
    sprite_to_texture_map = {}
    texture_map = {}
    groupData = {}
    for object in env.objects:
        if object.type in {Obj.Sprite, Obj.Texture2D, Obj.MonoBehaviour}:
            resource = object.read()
            if object.type == Obj.Sprite:
                # map this sprite to its texture (which we will use for compositing)
                sprite_to_texture_map[object.path_id] = resource.m_RD.texture.path_id
            if not isinstance(resource, Object):
                continue
            if object.type in {Obj.Sprite, Obj.Texture2D}:
                path_map[object.path_id] = resource
            elif object.type == Obj.MonoBehaviour and (script := resource.m_Script):
                tree = object.read_typetree()
                # dname = script.read().name broke in 2.5 but should be one of the 2 below:
                if 'spriteGroups' in tree: # AVGCharacterSpriteHubGroup
                    groupData = tree
                elif 'sprites' in tree: # AVGCharacterSpriteHub
                    groupData['spriteGroups'] = [{'sprites':tree['sprites'],'facePos':tree.get('facePos',tree['FacePos']), 'faceSize': tree.get('faceSize',tree['FaceSize'])}]
    texture_map = {k: path_map[v] for k, v in sprite_to_texture_map.items()}
    if len(path_map) == 0:
        print('No images found, skipping...')
        return None
    for bodyNum,body in enumerate(groupData['spriteGroups']):
        face_rect = {
            'x': int(body['facePos']['x']),
            'y': int(body['facePos']['y']),
            'w': int(body['faceSize']['x']),
            'h': int(body['faceSize']['y'])
        }

        isFullImages = not (face_rect['x'] >= 0 and face_rect['y'] >= 0)
        
        if not isFullImages:
            # load base image (last one in sprites) and apply alpha
            # alpha is always a Texture2D and never a Sprite, so we use path_map instead, on newer sprites alpha is baked in so alphaTex.m_PathID will be 0
            if body['sprites'][-1]['alphaTex']['m_PathID']:
                base = combine_alpha(texture_map[body['sprites'][-1]['sprite']['m_PathID']].image, path_map[body['sprites'][-1]['alphaTex']['m_PathID']].image)
            else:
                base = texture_map[body['sprites'][-1]['sprite']['m_PathID']].image.convert("RGBA")
            bw,bh = base.width,base.height
            # calculate face offset, thanks to arkwaifu.cc for this algorithm
            if bw == bh and bw < 1024:
                #scale to 1024
                for k in face_rect:
                    face_rect[k] = int(bw / 1024 * face_rect[k])
            # seems HG has fixed their data so these bottom 2 no longer occur:
            elif bw != bh and max(bw,bh) < 1024:
                # pad to 1024 (not on bottom)
                face_rect['x'] += (bw - 1024) // 2
                face_rect['y'] += bh - 1024
            elif bw != bh: # max is > 1024
                # pad to larger dimension
                face_rect['x'] += (bw - max(bw,bh)) // 2
                face_rect['y'] += (bh - max(bw,bh)) // 2
        for faceNum,face in enumerate(body['sprites']):
            dest_path = (output_dir / source_dir / f'{Path(next(iter(env.container.keys()))).stem}#{faceNum+1}${bodyNum+1}').with_suffix(".png")
            if face['alphaTex']['m_PathID'] and not next(iter(env.container.keys())).endswith('avg_6d5_1.prefab'): # except this one file
                face_img = combine_alpha(texture_map[face['sprite']['m_PathID']].image, path_map[face['alphaTex']['m_PathID']].image)
            else:
                face_img = texture_map[face['sprite']['m_PathID']].image.convert("RGBA")
            
            if isFullImages or face.get('isWholeBody',False):
                face_img.save(dest_path)
                face_img.close()
                continue
            if faceNum == len(body['sprites'])-1:
                # for non-full images, the last sprite is identical to the first, so don't save it.
                continue
            face_img = face_img.resize((face_rect['w'], face_rect['h']))
            complete_img = base.copy()
            complete_img.paste(face_img, (face_rect['x'], face_rect['y']))
            complete_img.save(dest_path)
            face_img.close()
            complete_img.close()
        if not isFullImages:
            base.close()
            
def combine_alpha(img_data, alpha_data):
    base = img_data.convert("RGBA")
    alpha = alpha_data.convert("L")
    assert(base.size == alpha.size)
    base.putalpha(alpha)
    alpha.close()
    return base
