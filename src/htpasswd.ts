import fs from 'fs';
import Path from 'path';

import { Callback, Config, IPluginAuth } from '@verdaccio/types';
import { unlockFile } from '@verdaccio/file-locking';

import { AuthConf, FileConf } from '../types';

import {
  verifyPassword,
  lockAndRead,
  parseHTPasswd,
  addUserToHTPasswd,
  changePasswordToHTPasswd,
  sanityCheck,
} from './utils';

export interface VerdaccioConfigApp extends Config {
  file: string;
}

/**
 * HTPasswd - Verdaccio auth class
 */
export default class HTPasswd implements IPluginAuth<VerdaccioConfigApp> {
  /**
   *
   * @param {*} config htpasswd files
   * @param {object} stuff config.yaml in object from
   */
  private users: {};
  private stuff: {};
  private files: FileConf[];
  private defaultConfig: FileConf;
  private verdaccioConfig: Config;
  private maxUsers: number;
  private path: string;
  private logger: {};

  // constructor
  public constructor(config: AuthConf, stuff: VerdaccioConfigApp) {
    this.users = {};

    // config for this module
    this.stuff = stuff;

    // verdaccio logger
    this.logger = stuff.logger;

    // verdaccio main config object
    this.verdaccioConfig = stuff.config;

    // all this "verdaccio_config" stuff is for b/w compatibility only

    const { files, max_users: maxUsers } = config;

    this.maxUsers = maxUsers || Infinity;
    this.files = files.map(item => ({
      ...item,
      path: Path.resolve(Path.dirname(this.verdaccioConfig.self_path), item.file),
    }));

    if (!files || !files.length) {
      throw new Error('should specify "files" in config');
    }

    const defaultConfig = this.files.find(item => item.isDefault);
    if (!defaultConfig || !defaultConfig.path) {
      throw new Error('A Defualt file should be specified in "files" ');
    }
    this.defaultConfig = defaultConfig;
    this.path = defaultConfig.path;
  }

  /**
   * authenticate - Authenticate user.
   * @param {string} user
   * @param {string} password
   * @param {function} cd
   * @returns {function}
   */
  public authenticate(user: string, password: string, cb: Callback): void {
    this.reload(err => {
      if (err) {
        return cb(err.code === 'ENOENT' ? null : err);
      }
      if (!this.users[user]) {
        return cb(null, false);
      }
      if (!verifyPassword(password, this.users[user].passwd)) {
        return cb(null, false);
      }
      return cb(null, this.users[user].groups);
    });
  }

  /**
   * Add user
   * 1. lock file for writing (other processes can still read)
   * 2. reload .htpasswd
   * 3. write new data into .htpasswd.tmp
   * 4. move .htpasswd.tmp to .htpasswd
   * 5. reload .htpasswd
   * 6. unlock file
   *
   * @param {string} user
   * @param {string} password
   * @param {function} realCb
   * @returns {function}
   */
  public adduser(user: string, password: string, realCb: Callback): any {
    const pathPass = this.path;
    let sanity = sanityCheck(user, password, verifyPassword, this.users, this.maxUsers);

    // preliminary checks, just to ensure that file won't be reloaded if it's
    // not needed
    if (sanity) {
      return realCb(sanity, false);
    }

    lockAndRead(pathPass, (err, res): void => {
      let locked = false;

      // callback that cleans up lock first
      const cb = (err): void => {
        if (locked) {
          unlockFile(pathPass, () => {
            // ignore any error from the unlock
            realCb(err, !err);
          });
        } else {
          realCb(err, !err);
        }
      };

      if (!err) {
        locked = true;
      }

      // ignore ENOENT errors, we'll just create .htpasswd in that case
      if (err && err.code !== 'ENOENT') {
        return cb(err);
      }
      const body = (res || '').toString('utf8');
      const defaultUsers = parseHTPasswd(body, this.defaultConfig.groupName, this.users);
      this.users = { ...this.users, ...defaultUsers };

      // real checks, to prevent race conditions
      // parsing users after reading file.
      sanity = sanityCheck(user, password, verifyPassword, this.users, this.maxUsers);

      if (sanity) {
        return cb(sanity);
      }

      try {
        this._writeFile(addUserToHTPasswd(body, user, password), cb);
      } catch (err) {
        return cb(err);
      }
    });
  }

  /**
   * Reload users
   * @param {function} callback
   */
  public reload(callback: Callback): void {
    const that = this;
    Promise.all(that.files.map(item => that._reloadFile(item)))
      .then(() => callback())
      .catch(err => callback(err));
  }

  private _reloadFile(item: FileConf): Promise<{}> {
    const { path: filePath, groupName, lastTime } = item;
    const oldUsers = this.users;
    if (!filePath) {
      return Promise.resolve({});
    }
    return new Promise((resolve, reject) => {
      fs.stat(filePath, (err, stats) => {
        if (err) {
          return reject(err);
        }
        if (lastTime === stats.mtime) {
          return resolve({});
        }

        item.lastTime = stats.mtime;

        fs.readFile(filePath, 'utf8', (err, buffer) => {
          if (err) {
            return reject(err);
          }

          Object.assign(oldUsers, parseHTPasswd(buffer, groupName, oldUsers));
          return resolve(parseHTPasswd(buffer, groupName, oldUsers));
        });
      });
    });
  }

  private _stringToUt8(authentication: string): string {
    return (authentication || '').toString();
  }

  private _writeFile(body: string, cb: Callback): void {
    fs.writeFile(this.path, body, err => {
      if (err) {
        cb(err);
      } else {
        this.reload(() => {
          cb(null);
        });
      }
    });
  }

  /**
   * changePassword - change password for existing user.
   * @param {string} user
   * @param {string} password
   * @param {function} cd
   * @returns {function}
   */
  public changePassword(user: string, password: string, newPassword: string, realCb: Callback): void {
    lockAndRead(this.path, (err, res) => {
      let locked = false;
      const pathPassFile = this.path;

      // callback that cleans up lock first
      const cb = (err): void => {
        if (locked) {
          unlockFile(pathPassFile, () => {
            // ignore any error from the unlock
            realCb(err, !err);
          });
        } else {
          realCb(err, !err);
        }
      };

      if (!err) {
        locked = true;
      }

      if (err && err.code !== 'ENOENT') {
        return cb(err);
      }

      const body = this._stringToUt8(res);
      const defaultUsers = parseHTPasswd(body, this.defaultConfig.groupName, this.users);
      this.users = { ...this.users, ...defaultUsers };

      if (!defaultUsers[user]) {
        return cb(new Error('User not found'));
      }

      try {
        this._writeFile(changePasswordToHTPasswd(body, user, password, newPassword), cb);
      } catch (err) {
        return cb(err);
      }
    });
  }
}
