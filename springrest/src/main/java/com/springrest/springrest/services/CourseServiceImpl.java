package com.springrest.springrest.services;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.springrest.springrest.dao.CourseDao;
import com.springrest.springrest.entities.Course;

@SuppressWarnings("unused")
@Service
public class CourseServiceImpl implements CourseService {

	@Autowired
	private CourseDao courseDao;
	
	//List<Course> list;
	
	public CourseServiceImpl() {
//		list = new ArrayList<>();
//		list.add(new Course(145, "Java", "This is java course"));
//		list.add(new Course(4343, "Python", "This is python course"));
	}
	
	@Override
	public List<Course> getCourses() {
		return courseDao.findAll();
	}

	
	@Override
	public Course getCourse(long courseId) {
		
//		Course c = null;
//		
//		for(Course course:list) {
//			if(course.getId() == courseId) {
//				c = course;
//				break;
//			}
//		}
		@SuppressWarnings("deprecation")
		Course entity = courseDao.getOne(courseId);
		return entity;
	}

	@Override
	public Course addCourse(Course course) {
		
//		list.add(course);
		courseDao.save(course);
		return course;
	}

	@Override
	public Course updateCourse(Course course) {
		
//		list.forEach(e -> {
//			if(e.getId() == course.getId()) {
//				e.setTitle(course.getTitle());
//				e.setDescription(course.getDescription());
//			}
//		});
		courseDao.save(course);
		return course;
	}

	@Override
	public void deleteCourse(long parseLong) {
//		list = this.list.stream().filter(e->e.getId()!=parseLong).collect(Collectors.toList());
		@SuppressWarnings("deprecation")
		Course entity = courseDao.getOne(parseLong);
		courseDao.delete(entity);
	}

}
