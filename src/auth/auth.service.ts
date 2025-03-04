import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';

import { InjectModel } from '@nestjs/mongoose';
import { User } from './entities/user.entity';
import { Model } from 'mongoose';
import * as bcryptjs from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload';
import { LoginResponse } from './interfaces/login-response';
import { RegisterUserDto, CreateUserDto, UpdateAuthDto, LoginDto } from './dto';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name)
    private userModel: Model<User>,
    private jwtService: JwtService
  ) {}

  async create(createUserDto: CreateUserDto): Promise<User> {
    try {
    
      const { password, ...userData } = createUserDto;

      const newUser = new this.userModel({
        ...userData,
        password: bcryptjs.hashSync(password, 10),
      });

      await newUser.save();
      const { password:_, ...user } = newUser.toJSON();

      return user;

    } catch (error) {
      if (error.code === 11000) { //El código 11000 indica que la llave está duplicad
        throw new BadRequestException(
          `User with email ${createUserDto.email} already exists`,
        );
      }
      throw new InternalServerErrorException('Something went wrong');
    }
  }

async register(registerDto: RegisterUserDto): Promise<LoginResponse>{

  const user = await this.create(registerDto);

  return {
    user,
    token: this.getJwtToken({ id: user._id! }),
  }
}

  async login(LoginDto: LoginDto):Promise<LoginResponse> {
    const { email, password } = LoginDto;

    const user = await this.userModel.findOne({ email });

    if (!user) {
      throw new UnauthorizedException(`User with email ${email} not found`);
    }

    if (!user.password || !bcryptjs.compareSync(password, user.password)) {
      throw new UnauthorizedException('Credentials are not valid (password)');
    }

    const { password:_, ...rest } = user.toJSON();

    return {
      user: rest,
      token: this.getJwtToken({ id:user.id }),
    }
  }

  findAll() {
    return this.userModel.find();
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  getJwtToken(payload: JwtPayload) {
    
    const token = this.jwtService.sign(payload);

    return token;
  }

  async findUserById(id: string) {
    const user = await this.userModel.findById(id);
    const { password, ...rest } = user!.toJSON();

    return rest;

  }
}
